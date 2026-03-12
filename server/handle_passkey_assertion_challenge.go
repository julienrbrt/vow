package server

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"

	"pkg.rbrt.fr/vow/internal/helpers"
	"pkg.rbrt.fr/vow/models"
)

// passkeyAssertionOptions is the JSON structure returned to the browser so it
// can call navigator.credentials.get(). It mirrors the
// PublicKeyCredentialRequestOptions WebAuthn type.
type passkeyAssertionOptions struct {
	Challenge        string              `json:"challenge"`
	AllowCredentials []allowedCredential `json:"allowCredentials"`
	Timeout          int                 `json:"timeout"`
	UserVerification string              `json:"userVerification"`
	RpID             string              `json:"rpId"`
}

type allowedCredential struct {
	ID   string `json:"id"`   // base64url-encoded credential ID
	Type string `json:"type"` // always "public-key"
}

// handlePasskeyAssertionChallenge returns WebAuthn PublicKeyCredentialRequestOptions
// for operations that need a fresh passkey assertion — currently only account
// deletion. The challenge is SHA-256("Delete account: <did>") so the server
// can reconstruct and verify it without storing session state.
//
//	POST /account/passkey-assertion-challenge
func (s *Server) handlePasskeyAssertionChallenge(w http.ResponseWriter, r *http.Request) {
	repo, ok := getContextValue[*models.RepoActor](r, contextKeyRepo)
	if !ok {
		helpers.UnauthorizedError(w, nil)
		return
	}

	if len(repo.AuthPublicKey) == 0 {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":   "NoSigningKey",
			"message": "No passkey is registered for this account.",
		})
		return
	}

	if len(repo.CredentialID) == 0 {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":   "NoCredentialID",
			"message": "No credential ID found for this account. Please re-register your passkey.",
		})
		return
	}

	// Derive a deterministic challenge so we can verify it server-side without
	// storing per-request state: SHA-256("Delete account: <did>").
	msg := fmt.Sprintf("Delete account: %s", repo.Repo.Did)
	sum := sha256.Sum256([]byte(msg))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	opts := passkeyAssertionOptions{
		Challenge: challenge,
		AllowCredentials: []allowedCredential{
			{
				ID:   base64.RawURLEncoding.EncodeToString(repo.CredentialID),
				Type: "public-key",
			},
		},
		Timeout:          30000,
		UserVerification: "preferred",
		RpID:             s.config.Hostname,
	}

	s.writeJSON(w, http.StatusOK, opts)
}
