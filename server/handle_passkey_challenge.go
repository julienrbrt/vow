package server

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"

	"pkg.rbrt.fr/vow/internal/helpers"
	"pkg.rbrt.fr/vow/models"
)

// passkeyCreationOptions is the JSON structure returned to the browser so it
// can call navigator.credentials.create(). It mirrors the
// PublicKeyCredentialCreationOptions WebAuthn type.
type passkeyCreationOptions struct {
	Rp   passkeyRp   `json:"rp"`
	User passkeyUser `json:"user"`
	// Challenge is a base64url-encoded random byte string. The browser passes
	// it through to the authenticator unchanged; the server doesn't need to
	// verify it later because the attestation is verified via the
	// clientDataJSON embedded in the attestationObject.
	Challenge        string                 `json:"challenge"`
	PubKeyCredParams []pubKeyCredParam      `json:"pubKeyCredParams"`
	AuthenticatorSel authenticatorSelection `json:"authenticatorSelection"`
	Attestation      string                 `json:"attestation"`
	Timeout          int                    `json:"timeout"`
}

type passkeyRp struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type passkeyUser struct {
	// ID is the base64url-encoded DID bytes. The WebAuthn spec requires it to
	// be opaque user-handle bytes, not a human-readable string.
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}

type pubKeyCredParam struct {
	Type string `json:"type"`
	Alg  int    `json:"alg"` // -7 = ES256 (P-256)
}

type authenticatorSelection struct {
	UserVerification string `json:"userVerification"`
	ResidentKey      string `json:"residentKey"`
}

// handlePasskeyChallenge returns WebAuthn PublicKeyCredentialCreationOptions
// so the browser can register a new passkey for the authenticated account.
//
//	POST /account/passkey-challenge
func (s *Server) handlePasskeyChallenge(w http.ResponseWriter, r *http.Request) {
	repo, ok := getContextValue[*models.RepoActor](r, contextKeyRepo)
	if !ok {
		helpers.UnauthorizedError(w, nil)
		return
	}

	// Generate a fresh 32-byte random challenge.
	challengeBytes := make([]byte, 32)
	if _, err := rand.Read(challengeBytes); err != nil {
		helpers.ServerError(w, nil)
		return
	}
	challenge := base64.RawURLEncoding.EncodeToString(challengeBytes)

	// Use the DID as the opaque user ID (base64url-encoded UTF-8 bytes).
	userID := base64.RawURLEncoding.EncodeToString([]byte(repo.Repo.Did))

	opts := passkeyCreationOptions{
		Rp: passkeyRp{
			ID:   s.config.Hostname,
			Name: "Vow PDS",
		},
		User: passkeyUser{
			ID:          userID,
			Name:        repo.Handle,
			DisplayName: repo.Handle,
		},
		Challenge: challenge,
		PubKeyCredParams: []pubKeyCredParam{
			{Type: "public-key", Alg: -7}, // ES256 / P-256
		},
		AuthenticatorSel: authenticatorSelection{
			UserVerification: "preferred",
			ResidentKey:      "preferred",
		},
		Attestation: "none",
		Timeout:     60000,
	}

	s.writeJSON(w, http.StatusOK, opts)
}
