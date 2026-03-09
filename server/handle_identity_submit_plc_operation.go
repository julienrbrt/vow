package server

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/bluesky-social/indigo/api/atproto"
	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/bluesky-social/indigo/events"
	"github.com/bluesky-social/indigo/util"
	"pkg.rbrt.fr/vow/internal/helpers"
	"pkg.rbrt.fr/vow/models"
	"pkg.rbrt.fr/vow/plc"
)

type ComAtprotoSubmitPlcOperationRequest struct {
	Operation plc.Operation `json:"operation"`
}

func (s *Server) handleSubmitPlcOperation(w http.ResponseWriter, r *http.Request) {
	logger := s.logger.With("name", "handleIdentitySubmitPlcOperation")

	repo, _ := getContextValue[*models.RepoActor](r, contextKeyRepo)

	var req ComAtprotoSubmitPlcOperationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Error("error decoding", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	if err := s.validator.Struct(req); err != nil {
		helpers.InputError(w, nil)
		return
	}

	if !strings.HasPrefix(repo.Repo.Did, "did:plc:") {
		helpers.InputError(w, nil)
		return
	}

	op := req.Operation

	k, err := atcrypto.ParsePrivateBytesK256(repo.SigningKey)
	if err != nil {
		logger.Error("error parsing key", "error", err)
		helpers.ServerError(w, nil)
		return
	}
	required, err := s.plcClient.CreateDidCredentials(k, "", repo.Handle)
	if err != nil {
		logger.Error("error creating did credentials", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	for _, expectedKey := range required.RotationKeys {
		if !slices.Contains(op.RotationKeys, expectedKey) {
			helpers.InputError(w, nil)
			return
		}
	}
	if op.Services["atproto_pds"].Type != "AtprotoPersonalDataServer" {
		helpers.InputError(w, nil)
		return
	}
	if op.Services["atproto_pds"].Endpoint != required.Services["atproto_pds"].Endpoint {
		helpers.InputError(w, nil)
		return
	}
	if op.VerificationMethods["atproto"] != required.VerificationMethods["atproto"] {
		helpers.InputError(w, nil)
		return
	}
	if op.AlsoKnownAs[0] != required.AlsoKnownAs[0] {
		helpers.InputError(w, nil)
		return
	}

	if err := s.plcClient.SendOperation(r.Context(), repo.Repo.Did, &op); err != nil {
		helpers.ServerError(w, nil)
		return
	}

	if err := s.passport.BustDoc(context.TODO(), repo.Repo.Did); err != nil {
		logger.Warn("error busting did doc", "error", err)
	}

	if err := s.evtman.AddEvent(context.TODO(), &events.XRPCStreamEvent{
		RepoIdentity: &atproto.SyncSubscribeRepos_Identity{
			Did:  repo.Repo.Did,
			Seq:  time.Now().UnixMicro(), // TODO: no
			Time: time.Now().Format(util.ISO8601),
		},
	}); err != nil {
		s.logger.Error("failed to add event", "error", err)
	}
}
