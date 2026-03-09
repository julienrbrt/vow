package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/bluesky-social/indigo/api/atproto"
	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/bluesky-social/indigo/events"
	"github.com/bluesky-social/indigo/util"
	"github.com/haileyok/cocoon/identity"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/haileyok/cocoon/plc"
)

type ComAtprotoIdentityUpdateHandleRequest struct {
	Handle string `json:"handle" validate:"atproto-handle"`
}

func (s *Server) handleIdentityUpdateHandle(w http.ResponseWriter, r *http.Request) {
	logger := s.logger.With("name", "handleIdentityUpdateHandle")

	repo, _ := getContextValue[*models.RepoActor](r, contextKeyRepo)

	var req ComAtprotoIdentityUpdateHandleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Error("error decoding", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	req.Handle = strings.ToLower(req.Handle)

	if err := s.validator.Struct(req); err != nil {
		helpers.InputError(w, nil)
		return
	}

	ctx := context.WithValue(r.Context(), "skip-cache", true)

	if strings.HasPrefix(repo.Repo.Did, "did:plc:") {
		log, err := identity.FetchDidAuditLog(ctx, nil, repo.Repo.Did)
		if err != nil {
			logger.Error("error fetching doc", "error", err)
			helpers.ServerError(w, nil)
			return
		}

		latest := log[len(log)-1]

		var newAka []string
		for _, aka := range latest.Operation.AlsoKnownAs {
			if aka == "at://"+repo.Handle {
				continue
			}
			newAka = append(newAka, aka)
		}

		newAka = append(newAka, "at://"+req.Handle)

		op := plc.Operation{
			Type:                "plc_operation",
			VerificationMethods: latest.Operation.VerificationMethods,
			RotationKeys:        latest.Operation.RotationKeys,
			AlsoKnownAs:         newAka,
			Services:            latest.Operation.Services,
			Prev:                &latest.Cid,
		}

		k, err := atcrypto.ParsePrivateBytesK256(repo.SigningKey)
		if err != nil {
			logger.Error("error parsing signing key", "error", err)
			helpers.ServerError(w, nil)
			return
		}

		if err := s.plcClient.SignOp(k, &op); err != nil {
			helpers.ServerError(w, nil)
			return
		}

		if err := s.plcClient.SendOperation(r.Context(), repo.Repo.Did, &op); err != nil {
			helpers.ServerError(w, nil)
			return
		}
	}

	if err := s.passport.BustDoc(context.TODO(), repo.Repo.Did); err != nil {
		logger.Warn("error busting did doc", "error", err)
	}

	s.evtman.AddEvent(context.TODO(), &events.XRPCStreamEvent{
		RepoIdentity: &atproto.SyncSubscribeRepos_Identity{
			Did:    repo.Repo.Did,
			Handle: to.StringPtr(req.Handle),
			Seq:    time.Now().UnixMicro(), // TODO: no
			Time:   time.Now().Format(util.ISO8601),
		},
	})

	if err := s.db.Exec(ctx, "UPDATE actors SET handle = ? WHERE did = ?", nil, req.Handle, repo.Repo.Did).Error; err != nil {
		logger.Error("error updating handle in db", "error", err)
		helpers.ServerError(w, nil)
		return
	}
}
