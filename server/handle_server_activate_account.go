package server

import (
	"context"
	"net/http"
	"time"

	"github.com/bluesky-social/indigo/api/atproto"
	"github.com/bluesky-social/indigo/events"
	"github.com/bluesky-social/indigo/util"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
)

type ComAtprotoServerActivateAccountRequest struct {
	// NOTE: this implementation will not pay attention to this value
	DeleteAfter time.Time `json:"deleteAfter"`
}

func (s *Server) handleServerActivateAccount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := s.logger.With("name", "handleServerActivateAccount")

	urepo, _ := getContextValue[*models.RepoActor](r, contextKeyRepo)

	if err := s.db.Exec(ctx, "UPDATE repos SET deactivated = ? WHERE did = ?", nil, false, urepo.Repo.Did).Error; err != nil {
		logger.Error("error updating account status to activated", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	s.evtman.AddEvent(context.TODO(), &events.XRPCStreamEvent{
		RepoAccount: &atproto.SyncSubscribeRepos_Account{
			Active: true,
			Did:    urepo.Repo.Did,
			Status: nil,
			Seq:    time.Now().UnixMicro(), // TODO: bad puppy
			Time:   time.Now().Format(util.ISO8601),
		},
	})

	w.WriteHeader(http.StatusOK)
}
