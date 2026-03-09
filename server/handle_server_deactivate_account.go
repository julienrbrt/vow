package server

import (
	"context"
	"net/http"
	"time"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/bluesky-social/indigo/api/atproto"
	"github.com/bluesky-social/indigo/events"
	"github.com/bluesky-social/indigo/util"
	"pkg.rbrt.fr/vow/internal/helpers"
	"pkg.rbrt.fr/vow/models"
)

type ComAtprotoServerDeactivateAccountRequest struct {
	// NOTE: this implementation will not pay attention to this value
	DeleteAfter time.Time `json:"deleteAfter"`
}

func (s *Server) handleServerDeactivateAccount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := s.logger.With("name", "handleServerDeactivateAccount")

	urepo, _ := getContextValue[*models.RepoActor](r, contextKeyRepo)

	if err := s.db.Exec(ctx, "UPDATE repos SET deactivated = ? WHERE did = ?", nil, true, urepo.Repo.Did).Error; err != nil {
		logger.Error("error updating account status to deactivated", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	s.evtman.AddEvent(context.TODO(), &events.XRPCStreamEvent{
		RepoAccount: &atproto.SyncSubscribeRepos_Account{
			Active: false,
			Did:    urepo.Repo.Did,
			Status: to.StringPtr("deactivated"),
			Seq:    time.Now().UnixMicro(), // TODO: bad puppy
			Time:   time.Now().Format(util.ISO8601),
		},
	})

	w.WriteHeader(http.StatusOK)
}
