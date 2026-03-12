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
	"pkg.rbrt.fr/vow/identity"
	"pkg.rbrt.fr/vow/internal/helpers"
	"pkg.rbrt.fr/vow/models"
	"pkg.rbrt.fr/vow/plc"
)

type ComAtprotoSubmitPlcOperationRequest struct {
	Operation plc.Operation `json:"operation"`
}

func (s *Server) handleSubmitPlcOperation(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
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

	// Validate the submitted operation against the current DID document and
	// the stored public key. We check:
	//   1. The signing key (verificationMethods.atproto) matches the registered key.
	//   2. The service endpoint still points to this PDS.
	//   3. The rotation keys include at least one key that was already authorised
	//      (either the user's passkey or the PDS key, depending on whether
	//      sovereignty has been transferred).
	//   4. The operation was signed by one of the current rotation keys (enforced
	//      by plc.directory on submission, not re-checked here).

	if len(repo.SigningPublicKey) == 0 {
		helpers.InputError(w, new("no signing key registered for this account"))
		return
	}

	pubKey, err := atcrypto.ParsePublicBytesP256(repo.SigningPublicKey)
	if err != nil {
		logger.Error("error parsing stored public key", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	// Fetch the current DID document to get the authoritative rotation keys.
	auditCtx := context.WithValue(ctx, identity.SkipCacheKey, true)
	auditLog, err := identity.FetchDidAuditLog(auditCtx, nil, repo.Repo.Did)
	if err != nil {
		logger.Error("error fetching DID audit log", "error", err)
		helpers.ServerError(w, nil)
		return
	}
	currentRotationKeys := auditLog[len(auditLog)-1].Operation.RotationKeys

	// The submitted operation must retain at least one of the current rotation
	// keys. This prevents an operation from locking out all authorised signers.
	hasAuthorisedRotationKey := false
	for _, rk := range op.RotationKeys {
		if slices.Contains(currentRotationKeys, rk) {
			hasAuthorisedRotationKey = true
			break
		}
	}
	if !hasAuthorisedRotationKey {
		helpers.InputError(w, new("operation must retain at least one current rotation key"))
		return
	}

	// The signing key must match the registered public key.
	userDIDKey := pubKey.DIDKey()
	if op.VerificationMethods["atproto"] != userDIDKey {
		helpers.InputError(w, new("verificationMethods.atproto must match the registered signing key"))
		return
	}

	// The service endpoint must still point to this PDS.
	required, err := s.plcClient.CreateDidCredentialsFromPublicKey(pubKey, "", repo.Handle)
	if err != nil {
		logger.Error("error creating did credentials", "error", err)
		helpers.ServerError(w, nil)
		return
	}
	if op.Services["atproto_pds"].Type != "AtprotoPersonalDataServer" {
		helpers.InputError(w, new("services.atproto_pds must be AtprotoPersonalDataServer"))
		return
	}
	if op.Services["atproto_pds"].Endpoint != required.Services["atproto_pds"].Endpoint {
		helpers.InputError(w, new("services.atproto_pds endpoint must point to this PDS"))
		return
	}

	if err := s.plcClient.SendOperation(r.Context(), repo.Repo.Did, &op); err != nil {
		helpers.ServerError(w, nil)
		return
	}

	if err := s.passport.BustDoc(ctx, repo.Repo.Did); err != nil {
		logger.Warn("error busting did doc", "error", err)
	}

	if err := s.evtman.AddEvent(ctx, &events.XRPCStreamEvent{
		RepoIdentity: &atproto.SyncSubscribeRepos_Identity{
			Did:  repo.Repo.Did,
			Seq:  time.Now().UnixMicro(), // TODO: no
			Time: time.Now().Format(util.ISO8601),
		},
	}); err != nil {
		s.logger.Error("failed to add event", "error", err)
	}
}
