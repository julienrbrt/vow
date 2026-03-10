package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/bluesky-social/indigo/api/atproto"
	"github.com/bluesky-social/indigo/events"
	"github.com/bluesky-social/indigo/util"
	"github.com/google/uuid"
	"pkg.rbrt.fr/vow/identity"
	"pkg.rbrt.fr/vow/internal/helpers"
	"pkg.rbrt.fr/vow/models"
	"pkg.rbrt.fr/vow/plc"
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

	ctx := context.WithValue(r.Context(), identity.SkipCacheKey, true)

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

		// Determine whether the PDS rotation key still has authority over
		// this DID. After supplySigningKey transfers the rotation key to the
		// user's wallet, the PDS key is no longer in the rotation key list
		// and cannot sign PLC operations.
		pdsRotationDIDKey := s.plcClient.RotationDIDKey()
		pdsCanSign := slices.Contains(latest.Operation.RotationKeys, pdsRotationDIDKey)

		if pdsCanSign {
			// PDS still holds authority — sign directly.
			if err := s.plcClient.SignOp(&op); err != nil {
				logger.Error("error signing PLC operation with rotation key", "error", err)
				helpers.ServerError(w, nil)
				return
			}
		} else {
			// Rotation key belongs to the user's wallet. Delegate the
			// signing to the signer over WebSocket, same as
			// handleSignPlcOperation does for other PLC operations.
			if !s.signerHub.IsConnected(repo.Repo.Did) {
				helpers.InputError(w, new("SignerNotConnected"))
				return
			}

			opCBOR, err := op.MarshalCBOR()
			if err != nil {
				logger.Error("error marshalling PLC op to CBOR", "error", err)
				helpers.ServerError(w, nil)
				return
			}

			requestID := uuid.NewString()
			expiresAt := time.Now().Add(signerRequestTimeout)

			pendingOps := []PendingWriteOp{
				{
					Type:       "plc_operation",
					Collection: "identity",
					Rkey:       req.Handle,
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
			if err != nil {
				switch err {
				case ErrSignerNotConnected:
					helpers.InputError(w, new("SignerNotConnected"))
				case ErrSignerRejected:
					helpers.InputError(w, new("SignatureRejected"))
				case ErrSignerTimeout:
					helpers.InputError(w, new("SignerTimeout"))
				default:
					logger.Error("signer error", "error", err)
					helpers.ServerError(w, nil)
				}
				return
			}

			op.Sig = base64.RawURLEncoding.EncodeToString(sigBytes)
		}

		if err := s.plcClient.SendOperation(r.Context(), repo.Repo.Did, &op); err != nil {
			logger.Error("error sending PLC operation", "error", err)
			helpers.ServerError(w, nil)
			return
		}
	}

	if err := s.passport.BustDoc(ctx, repo.Repo.Did); err != nil {
		logger.Warn("error busting did doc", "error", err)
	}

	if err := s.evtman.AddEvent(ctx, &events.XRPCStreamEvent{
		RepoIdentity: &atproto.SyncSubscribeRepos_Identity{
			Did:    repo.Repo.Did,
			Handle: new(req.Handle),
			Seq:    time.Now().UnixMicro(), // TODO: no
			Time:   time.Now().Format(util.ISO8601),
		},
	}); err != nil {
		s.logger.Error("failed to add event", "error", err)
	}

	if err := s.db.Exec(ctx, "UPDATE actors SET handle = ? WHERE did = ?", nil, req.Handle, repo.Repo.Did).Error; err != nil {
		logger.Error("error updating handle in db", "error", err)
		helpers.ServerError(w, nil)
		return
	}
}
