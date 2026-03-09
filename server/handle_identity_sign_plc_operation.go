package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/haileyok/cocoon/identity"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/haileyok/cocoon/plc"
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
		helpers.InputError(w, to.StringPtr("InvalidToken"))
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

	ctx := context.WithValue(r.Context(), "skip-cache", true)
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

	k, err := atcrypto.ParsePrivateBytesK256(repo.SigningKey)
	if err != nil {
		logger.Error("error parsing signing key", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	if err := s.plcClient.SignOp(k, &op); err != nil {
		logger.Error("error signing plc operation", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	if err := s.db.Exec(ctx, "UPDATE repos SET plc_operation_code = NULL, plc_operation_code_expires_at = NULL WHERE did = ?", nil, repo.Repo.Did).Error; err != nil {
		logger.Error("error updating repo", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	s.writeJSON(w, 200, ComAtprotoSignPlcOperationResponse{
		Operation: op,
	})
}
