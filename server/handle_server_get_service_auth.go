package server

import (
	"context"
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

	var token string
	var err error
	if repo.CompatMode {
		token, err = s.requestUserSignedServiceAuthJWT(r.Context(), repo, req.Aud, req.Lxm, exp)
	} else {
		token, err = s.signServiceAuthJWT(repo, req.Aud, req.Lxm, exp)
	}

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

// requestUserSignedServiceAuthJWT returns a user-signed ES256K service-auth JWT.
func (s *Server) requestUserSignedServiceAuthJWT(
	ctx context.Context,
	repo *models.RepoActor,
	aud string,
	lxm string,
	exp int64,
) (string, error) {
	did := repo.Repo.Did
	now := time.Now().Unix()
	if exp == 0 {
		exp = now + int64(5*time.Minute/time.Second)
	}

	header := map[string]string{
		"alg": "ES256K",
		"typ": "JWT",
		"kid": did + "#atproto",
	}
	hj, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("error marshaling header: %w", err)
	}
	encheader := strings.TrimRight(base64.RawURLEncoding.EncodeToString(hj), "=")

	payload := map[string]any{
		"iss": did,
		"aud": aud,
		"jti": uuid.NewString(),
		"exp": exp,
		"iat": now,
	}
	if lxm != "" {
		payload["lxm"] = lxm
	}
	pj, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("error marshaling payload: %w", err)
	}
	encpayload := strings.TrimRight(base64.RawURLEncoding.EncodeToString(pj), "=")

	signingString := fmt.Sprintf("%s.%s", encheader, encpayload)

	// Request a signature from the user's browser via the WebSocket connection.
	requestID := uuid.NewString()
	msg, err := s.buildSignJWTRequestMsg(requestID, base64.RawURLEncoding.EncodeToString([]byte(signingString)), aud, lxm)
	if err != nil {
		return "", fmt.Errorf("marshalling sign_jwt_request: %w", err)
	}

	sig, err := s.signerHub.RequestSignature(ctx, did, requestID, msg)
	if err != nil {
		return "", err // Includes ErrSignerNotConnected, context cancellation, etc.
	}

	// Append the signature to the token.
	encsig := strings.TrimRight(base64.RawURLEncoding.EncodeToString(sig), "=")
	return signingString + "." + encsig, nil
}

// signServiceAuthJWT returns a signed ES256 service-auth JWT for the given
// (aud, lxm) pair.
//
// Service-auth JWTs are signed by the PDS server key stored in the atproto_service
// slot of the user's DID document. This is a standard ES256 signature over
// SHA-256(header.payload), which external AppViews and relays can verify without
// any passkey interaction. The passkey (atproto slot) is reserved for repo commit
// signing only — operations that are user-initiated and can tolerate passkey usage.
// Background infrastructure requests like feed loading must not require one.
//
// lxm may be empty, in which case no "lxm" claim is included.
func (s *Server) signServiceAuthJWT(
	repo *models.RepoActor,
	aud string,
	lxm string,
	exp int64,
) (string, error) {
	did := repo.Repo.Did
	now := time.Now().Unix()
	if exp == 0 {
		exp = now + int64(5*time.Minute/time.Second)
	}

	header := map[string]string{
		"alg": "ES256",
		"typ": "JWT",
		"kid": did + "#atproto_service",
	}
	hj, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("error marshaling header: %w", err)
	}
	encheader := base64.RawURLEncoding.EncodeToString(hj)

	payload := map[string]any{
		"iss": did,
		"aud": aud,
		"jti": uuid.NewString(),
		"exp": exp,
		"iat": now,
	}
	if lxm != "" {
		payload["lxm"] = lxm
	}
	pj, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("error marshaling payload: %w", err)
	}
	encpayload := strings.TrimRight(base64.RawURLEncoding.EncodeToString(pj), "=")

	signingString := fmt.Sprintf("%s.%s", encheader, encpayload)

	sig, err := s.privateKeyATP.HashAndSign([]byte(signingString))
	if err != nil {
		return "", fmt.Errorf("signing failed: %w", err)
	}

	encsig := strings.TrimRight(base64.RawURLEncoding.EncodeToString(sig), "=")
	return signingString + "." + encsig, nil
}
