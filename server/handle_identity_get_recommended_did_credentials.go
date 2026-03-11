package server

import (
	"context"
	"net/http"
	"strings"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"pkg.rbrt.fr/vow/identity"
	"pkg.rbrt.fr/vow/internal/helpers"
	"pkg.rbrt.fr/vow/models"
)

func (s *Server) handleGetRecommendedDidCredentials(w http.ResponseWriter, r *http.Request) {
	logger := s.logger.With("name", "handleIdentityGetRecommendedDidCredentials")

	repo, _ := getContextValue[*models.RepoActor](r, contextKeyRepo)

	if len(repo.PublicKey) == 0 {
		helpers.InputError(w, new("no signing key registered for this account"))
		return
	}

	pubKey, err := atcrypto.ParsePublicBytesP256(repo.PublicKey)
	if err != nil {
		logger.Error("error parsing stored public key", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	// Start with the PDS-generated credentials (verification methods, services,
	// alsoKnownAs). These are always correct regardless of rotation key state.
	creds, err := s.plcClient.CreateDidCredentialsFromPublicKey(pubKey, "", repo.Handle)
	if err != nil {
		logger.Error("error creating did credentials", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	// If this is a did:plc identity, fetch the actual rotation keys from the
	// current PLC document. After supplySigningKey transfers the rotation key
	// to the user's passkey, the PDS key is no longer authoritative and we
	// must reflect the real state.
	if strings.HasPrefix(repo.Repo.Did, "did:plc:") {
		ctx := context.WithValue(r.Context(), identity.SkipCacheKey, true)
		auditLog, err := identity.FetchDidAuditLog(ctx, nil, repo.Repo.Did)
		if err != nil {
			logger.Warn("error fetching DID audit log for recommended credentials, falling back to PDS defaults", "error", err)
			// Fall through — the PDS-generated rotation keys are a reasonable
			// fallback if we can't reach plc.directory.
		} else {
			latest := auditLog[len(auditLog)-1]
			creds.RotationKeys = latest.Operation.RotationKeys
		}
	}

	s.writeJSON(w, 200, creds)
}
