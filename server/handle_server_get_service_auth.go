package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/google/uuid"
	"pkg.rbrt.fr/vow/internal/helpers"
	"pkg.rbrt.fr/vow/models"
	secp256k1secec "gitlab.com/yawning/secp256k1-voi/secec"
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
		exp = now + 60 // default
	}

	if req.Lxm == "com.atproto.server.getServiceAuth" {
		helpers.InputError(w, to.StringPtr("may not generate auth tokens recursively"))
		return
	}

	var maxExp int64
	if req.Lxm != "" {
		maxExp = now + (60 * 60)
	} else {
		maxExp = now + 60
	}
	if exp > maxExp {
		helpers.InputError(w, to.StringPtr("expiration too big. smoller please"))
		return
	}

	repo, _ := getContextValue[*models.RepoActor](r, contextKeyRepo)

	header := map[string]string{
		"alg": "ES256K",
		"crv": "secp256k1",
		"typ": "JWT",
	}
	hj, err := json.Marshal(header)
	if err != nil {
		logger.Error("error marshaling header", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	encheader := strings.TrimRight(base64.RawURLEncoding.EncodeToString(hj), "=")

	payload := map[string]any{
		"iss": repo.Repo.Did,
		"aud": req.Aud,
		"jti": uuid.NewString(),
		"exp": exp,
		"iat": now,
	}
	if req.Lxm != "" {
		payload["lxm"] = req.Lxm
	}
	pj, err := json.Marshal(payload)
	if err != nil {
		logger.Error("error marshaling payload", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	encpayload := strings.TrimRight(base64.RawURLEncoding.EncodeToString(pj), "=")

	input := fmt.Sprintf("%s.%s", encheader, encpayload)
	hash := sha256.Sum256([]byte(input))

	sk, err := secp256k1secec.NewPrivateKey(repo.SigningKey)
	if err != nil {
		logger.Error("can't load private key", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	R, S, _, err := sk.SignRaw(rand.Reader, hash[:])
	if err != nil {
		logger.Error("error signing", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	rBytes := R.Bytes()
	sBytes := S.Bytes()

	rPadded := make([]byte, 32)
	sPadded := make([]byte, 32)
	copy(rPadded[32-len(rBytes):], rBytes)
	copy(sPadded[32-len(sBytes):], sBytes)

	rawsig := append(rPadded, sPadded...)
	encsig := strings.TrimRight(base64.RawURLEncoding.EncodeToString(rawsig), "=")
	token := fmt.Sprintf("%s.%s", input, encsig)

	s.writeJSON(w, 200, map[string]string{
		"token": token,
	})
}
