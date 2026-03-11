package server

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/golang-jwt/jwt/v4"
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

	claims := jwt.MapClaims{
		"iss": did,
		"aud": aud,
		"jti": uuid.NewString(),
		"exp": exp,
		"iat": now,
	}
	if lxm != "" {
		claims["lxm"] = lxm
	}

	// Register a custom ES256 signing method that delegates to atcrypto so the
	// signature is always low-S normalised, as the ATProto spec requires.
	token := jwt.NewWithClaims(newES256AtpSigningMethod(), claims)
	return token.SignedString(s.privateKeyATP)
}

// es256AtpSigningMethod is a jwt.SigningMethod that uses atcrypto.PrivateKeyP256
// to produce low-S normalised ES256 signatures, satisfying the ATProto spec.
type es256AtpSigningMethod struct{}

func newES256AtpSigningMethod() *es256AtpSigningMethod { return &es256AtpSigningMethod{} }

func (m *es256AtpSigningMethod) Alg() string { return "ES256" }

func (m *es256AtpSigningMethod) Sign(signingString string, key any) (string, error) {
	priv, ok := key.(*atcrypto.PrivateKeyP256)
	if !ok {
		return "", fmt.Errorf("es256AtpSigningMethod: expected *atcrypto.PrivateKeyP256, got %T", key)
	}
	sig, err := priv.HashAndSign([]byte(signingString))
	if err != nil {
		return "", fmt.Errorf("es256AtpSigningMethod: signing failed: %w", err)
	}
	return jwt.EncodeSegment(sig), nil //nolint:staticcheck
}

func (m *es256AtpSigningMethod) Verify(signingString string, signature string, key any) error {
	sigBytes, err := jwt.DecodeSegment(signature) //nolint:staticcheck
	if err != nil {
		return err
	}
	pub, ok := key.(atcrypto.PublicKey)
	if !ok {
		return fmt.Errorf("es256AtpSigningMethod: expected atcrypto.PublicKey, got %T", key)
	}
	return pub.HashAndVerifyLenient([]byte(signingString), sigBytes)
}

// pdsDIDKey returns the PDS server's P-256 public key encoded as a did:key
// string. This is what gets written into verificationMethods["atproto_service"]
// of the user's DID document during supplySigningKey.
func (s *Server) pdsDIDKey() (string, error) {
	pub, err := s.privateKeyATP.PublicKey()
	if err != nil {
		return "", fmt.Errorf("getting PDS public key: %w", err)
	}
	return pub.DIDKey(), nil
}
