package server

import (
	"fmt"
	"net/http"
	"time"

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

	if !s.signerHub.IsConnected(repo.Repo.Did) {
		helpers.InputError(w, new("SignerNotConnected"))
		return
	}

	token, err := s.signServiceAuthJWT(r.Context(), repo, req.Aud, req.Lxm, exp)
	if err != nil {
		switch err {
		case ErrSignerNotConnected:
			helpers.InputError(w, new("SignerNotConnected"))
		case ErrSignerRejected:
			helpers.InputError(w, new("SignatureRejected"))
		case ErrSignerTimeout:
			helpers.InputError(w, new("SignerTimeout"))
		default:
			logger.Error("error signing service auth JWT", "error", err)
			helpers.ServerError(w, nil)
		}
		return
	}

	s.writeJSON(w, 200, map[string]string{
		"token": token,
	})
}
