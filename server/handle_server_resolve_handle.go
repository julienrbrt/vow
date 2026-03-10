package server

import (
	"context"
	"net/http"

	"pkg.rbrt.fr/vow/identity"

	"github.com/bluesky-social/indigo/atproto/syntax"
	"pkg.rbrt.fr/vow/internal/helpers"
)

func (s *Server) handleResolveHandle(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := s.logger.With("name", "handleServerResolveHandle")

	type Resp struct {
		Did string `json:"did"`
	}

	handle := r.URL.Query().Get("handle")

	if handle == "" {
		helpers.InputError(w, new("Handle must be supplied in request."))
		return
	}

	parsed, err := syntax.ParseHandle(handle)
	if err != nil {
		helpers.InputError(w, new("Invalid handle."))
		return
	}

	// Check local accounts first before hitting DNS / well-known.
	if actor, err := s.getActorByHandle(ctx, parsed.String()); err == nil {
		s.writeJSON(w, 200, Resp{Did: actor.Did})
		return
	}

	did, err := s.passport.ResolveHandle(
		context.WithValue(ctx, identity.SkipCacheKey, true),
		parsed.String(),
	)
	if err != nil {
		logger.Error("error resolving handle", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	s.writeJSON(w, 200, Resp{
		Did: did,
	})
}
