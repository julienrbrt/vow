package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"pkg.rbrt.fr/vow/identity"
	"pkg.rbrt.fr/vow/internal/helpers"
	"pkg.rbrt.fr/vow/models"
	"pkg.rbrt.fr/vow/plc"
)

type ComAtprotoSignPlcOperationRequest struct {
	Token               string                                `json:"token"`
	VerificationMethods *map[string]string                    `json:"verificationMethods"`
	RotationKeys        *[]string                             `json:"rotationKeys"`
	AlsoKnownAs         *[]string                             `json:"alsoKnownAs"`
	Services            *map[string]identity.OperationService `json:"services"`
}

type ComAtprotoSignPlcOperationResponse struct {
	Operation plc.Operation `json:"operation"`
}

// handleSignPlcOperation builds a PLC operation from the request fields,
// sends the CBOR-encoded payload to the user's signer for signing via the
// SignerHub WebSocket, then returns the signed operation so the client
// can submit it to the PLC directory.
//
// Unlike the previous implementation this handler never touches a private key.
// The rotation key (held by the PDS) signs the PLC operation envelope as
// required by the PLC protocol; the user's signing key (held in their passkey)
// signs only the inner payload bytes delivered over the WebSocket.
func (s *Server) handleSignPlcOperation(w http.ResponseWriter, r *http.Request) {
	logger := s.logger.With("name", "handleSignPlcOperation")

	repo, _ := getContextValue[*models.RepoActor](r, contextKeyRepo)

	var req ComAtprotoSignPlcOperationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Error("error decoding", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	if !strings.HasPrefix(repo.Repo.Did, "did:plc:") {
		helpers.InputError(w, nil)
		return
	}

	if repo.PlcOperationCode == nil || repo.PlcOperationCodeExpiresAt == nil {
		helpers.InputError(w, new("InvalidToken"))
		return
	}

	if *repo.PlcOperationCode != req.Token {
		helpers.InvalidTokenError(w)
		return
	}

	if time.Now().UTC().After(*repo.PlcOperationCodeExpiresAt) {
		helpers.ExpiredTokenError(w)
		return
	}

	// Fetch the current DID document so we can build on the latest operation.
	ctx := context.WithValue(r.Context(), identity.SkipCacheKey, true)
	log, err := identity.FetchDidAuditLog(ctx, nil, repo.Repo.Did)
	if err != nil {
		logger.Error("error fetching doc", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	latest := log[len(log)-1]

	op := plc.Operation{
		Type:                "plc_operation",
		VerificationMethods: latest.Operation.VerificationMethods,
		RotationKeys:        latest.Operation.RotationKeys,
		AlsoKnownAs:         latest.Operation.AlsoKnownAs,
		Services:            latest.Operation.Services,
		Prev:                &latest.Cid,
	}
	if req.VerificationMethods != nil {
		op.VerificationMethods = *req.VerificationMethods
	}
	if req.RotationKeys != nil {
		op.RotationKeys = *req.RotationKeys
	}
	if req.AlsoKnownAs != nil {
		op.AlsoKnownAs = *req.AlsoKnownAs
	}
	if req.Services != nil {
		op.Services = *req.Services
	}

	// Serialise the operation to CBOR — this is the payload the user's passkey
	// must sign. We send it to the signer and wait for the signature.
	opCBOR, err := op.MarshalCBOR()
	if err != nil {
		logger.Error("error marshalling PLC op to CBOR", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	requestID := uuid.NewString()
	expiresAt := time.Now().Add(signerRequestTimeout)

	// Summarise the operation for the signer's approval UI.
	pendingOps := []PendingWriteOp{
		{
			Type:       "plc_operation",
			Collection: "identity",
		},
	}

	payloadB64 := base64.RawURLEncoding.EncodeToString(opCBOR)
	msgBytes, err := buildSignRequestMsg(requestID, repo.Repo.Did, payloadB64, pendingOps, expiresAt)
	if err != nil {
		logger.Error("error building sign request message", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	signCtx, cancel := context.WithDeadline(r.Context(), expiresAt)
	defer cancel()

	sigBytes, err := s.signerHub.RequestSignature(signCtx, repo.Repo.Did, requestID, msgBytes)
	if helpers.HandleSignerError(w, err) {
		logger.Error("signer error during PLC operation signing", "did", repo.Repo.Did, "error", err)
		return
	}

	// Attach the user's signature to the operation.
	op.Sig = base64.RawURLEncoding.EncodeToString(sigBytes)

	// Clear the one-time token now that it has been consumed.
	if err := s.db.Exec(ctx,
		"UPDATE repos SET plc_operation_code = NULL, plc_operation_code_expires_at = NULL WHERE did = ?",
		nil, repo.Repo.Did,
	).Error; err != nil {
		logger.Error("error clearing plc operation code", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	logger.Info("PLC operation signed via signer",
		"did", repo.Repo.Did,
		"requestId", requestID,
	)

	s.writeJSON(w, 200, ComAtprotoSignPlcOperationResponse{
		Operation: op,
	})
}
