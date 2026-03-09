package server

import (
	"net/http"

	"github.com/haileyok/cocoon/internal/helpers"
)

type ComAtprotoSyncGetRepoStatusResponse struct {
	Did    string  `json:"did"`
	Active bool    `json:"active"`
	Status *string `json:"status,omitempty"`
	Rev    *string `json:"rev,omitempty"`
}

// TODO: make this actually do the right thing
func (s *Server) handleSyncGetRepoStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := s.logger.With("name", "handleSyncGetRepoStatus")

	did := r.URL.Query().Get("did")
	if did == "" {
		helpers.InputError(w, nil)
		return
	}

	urepo, err := s.getRepoActorByDid(ctx, did)
	if err != nil {
		logger.Error("could not find repo", "did", did, "error", err)
		helpers.ServerError(w, nil)
		return
	}

	s.writeJSON(w, http.StatusOK, ComAtprotoSyncGetRepoStatusResponse{
		Did:    urepo.Repo.Did,
		Active: urepo.Active(),
		Status: urepo.Status(),
		Rev:    &urepo.Rev,
	})
}
