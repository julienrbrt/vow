package server

import (
	"net/http"

	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/ipfs/go-cid"
)

type ComAtprotoSyncGetLatestCommitResponse struct {
	Cid string `json:"string"`
	Rev string `json:"rev"`
}

func (s *Server) handleSyncGetLatestCommit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := s.logger.With("name", "handleSyncGetLatestCommit")

	did := r.URL.Query().Get("did")
	if did == "" {
		helpers.InputError(w, nil)
		return
	}

	urepo, err := s.getRepoActorByDid(ctx, did)
	if err != nil {
		logger.Error("could not find repo", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	c, err := cid.Cast(urepo.Root)
	if err != nil {
		logger.Error("could not cast root cid", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	s.writeJSON(w, http.StatusOK, ComAtprotoSyncGetLatestCommitResponse{
		Cid: c.String(),
		Rev: urepo.Rev,
	})
}
