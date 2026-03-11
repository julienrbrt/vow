package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"pkg.rbrt.fr/vow/internal/helpers"
	"pkg.rbrt.fr/vow/models"
)

type ServerGetServiceAuthRequest struct {
	Aud string  `query:"aud" validate:"required,atproto-did"`
	Exp float64 `query:"exp"`
	Lxm string  `query:"lxm"`
}

func (s *Server) handleServerGetServiceAuth(w http.ResponseWriter, r *http.Request) {
	logger := s.logger.With("name", "handleServerGetServiceAuth")

	req := ServerGetServiceAuthRequest{
		Aud: r.URL.Query().Get("aud"),
		Lxm: r.URL.Query().Get("lxm"),
	}
	if v := r.URL.Query().Get("exp"); v != "" {
		var exp float64
		if _, err := fmt.Sscanf(v, "%f", &exp); err == nil {
			req.Exp = exp
		}
	}

	if err := s.validator.Struct(req); err != nil {
		helpers.InputError(w, nil)
		return
	}

	exp := int64(req.Exp)
	now := time.Now().Unix()
	if exp == 0 {
		exp = now + 60
	}

	if req.Lxm == "com.atproto.server.getServiceAuth" {
		helpers.InputError(w, new("may not generate auth tokens recursively"))
		return
	}

	var maxExp int64
	if req.Lxm != "" {
		maxExp = now + (60 * 60)
	} else {
		maxExp = now + 60
	}
	if exp > maxExp {
		helpers.InputError(w, new("expiration too big. smoller please"))
		return
	}

	repo, _ := getContextValue[*models.RepoActor](r, contextKeyRepo)

	token, err := s.signServiceAuthJWT(r.Context(), repo, req.Aud, req.Lxm, exp)
	if helpers.HandleSignerError(w, err) {
		logger.Error("error signing service auth JWT", "error", err)
		return
	}
	if err != nil {
		logger.Error("error signing service auth JWT", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	s.writeJSON(w, 200, map[string]string{
		"token": token,
	})
}

// signServiceAuthJWT returns a signed ES256 service-auth JWT for the given
// (aud, lxm) pair. It sends a signing request to the user's passkey via the
// SignerHub WebSocket and waits for the verified raw (r‖s) signature.
//
// The returned string is a fully formed "header.payload.signature" JWT ready to
// be placed in an Authorization: Bearer header.
//
// lxm may be empty, in which case no "lxm" claim is included.
func (s *Server) signServiceAuthJWT(
	ctx context.Context,
	repo *models.RepoActor,
	aud string,
	lxm string,
	exp int64,
) (string, error) {
	if len(repo.PublicKey) == 0 {
		return "", fmt.Errorf("no public key registered for account %s", repo.Repo.Did)
	}

	did := repo.Repo.Did

	// ── Build header + payload ────────────────────────────────────────────
	header := map[string]string{
		"alg": "ES256",
		"crv": "P-256",
		"typ": "JWT",
	}
	hj, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshaling JWT header: %w", err)
	}
	encHeader := strings.TrimRight(base64.RawURLEncoding.EncodeToString(hj), "=")

	now := time.Now().Unix()
	var expiresAt time.Time
	if exp == 0 {
		expiresAt = time.Now().Add(5 * time.Minute)
		exp = expiresAt.Unix()
	} else {
		expiresAt = time.Unix(exp, 0)
	}

	claims := map[string]any{
		"iss": did,
		"aud": aud,
		"jti": uuid.NewString(),
		"exp": exp,
		"iat": now,
	}
	if lxm != "" {
		claims["lxm"] = lxm
	}

	pj, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshaling JWT payload: %w", err)
	}
	encPayload := strings.TrimRight(base64.RawURLEncoding.EncodeToString(pj), "=")

	// signingInput is what the JWT spec calls the "message to be signed":
	// base64url(header) + "." + base64url(payload).
	signingInput := encHeader + "." + encPayload

	// ES256 requires signing the SHA-256 hash of the signing input. We send
	// the hash as the WebAuthn challenge (the passkey will sign
	// authenticatorData ‖ SHA-256(clientDataJSON) where clientDataJSON.challenge
	// = base64url(hash)). The WS handler verifies the full assertion and
	// delivers the raw (r‖s) signature bytes back to this function.
	hash := sha256.Sum256([]byte(signingInput))
	payloadB64 := base64.RawURLEncoding.EncodeToString(hash[:])

	requestID := uuid.NewString()
	signerDeadline := time.Now().Add(signerRequestTimeout)

	ops := []PendingWriteOp{
		{
			Type:       "service_auth",
			Collection: aud,
			Rkey:       lxm,
		},
	}

	msgBytes, err := buildSignRequestMsg(requestID, did, payloadB64, ops, signerDeadline)
	if err != nil {
		return "", fmt.Errorf("building sign request message: %w", err)
	}

	signCtx, cancel := context.WithDeadline(ctx, signerDeadline)
	defer cancel()

	sigBytes, err := s.signerHub.RequestSignature(signCtx, did, requestID, msgBytes)
	if err != nil {
		return "", err
	}

	// sigBytes is the raw 64-byte (r‖s) P-256 signature delivered by the WS
	// handler after WebAuthn assertion verification. Trim to 64 bytes just in
	// case an old client appended a recovery byte.
	if len(sigBytes) == 65 {
		sigBytes = sigBytes[:64]
	}
	if len(sigBytes) != 64 {
		return "", fmt.Errorf("unexpected signature length %d (want 64)", len(sigBytes))
	}

	encSig := strings.TrimRight(base64.RawURLEncoding.EncodeToString(sigBytes), "=")
	token := signingInput + "." + encSig

	return token, nil
}
