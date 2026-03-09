package server

import (
	"context"
	"net/http"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/haileyok/cocoon/internal/helpers"
)

func (s *Server) handleResolveHandle(w http.ResponseWriter, r *http.Request) {
	logger := s.logger.With("name", "handleServerResolveHandle")

	type Resp struct {
		Did string `json:"did"`
	}

	handle := r.URL.Query().Get("handle")

	if handle == "" {
		helpers.InputError(w, to.StringPtr("Handle must be supplied in request."))
		return
	}

	parsed, err := syntax.ParseHandle(handle)
	if err != nil {
		helpers.InputError(w, to.StringPtr("Invalid handle."))
		return
	}

	ctx := context.WithValue(r.Context(), "skip-cache", true)
	did, err := s.passport.ResolveHandle(ctx, parsed.String())
	if err != nil {
		logger.Error("error resolving handle", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	s.writeJSON(w, 200, Resp{
		Did: did,
	})
}
