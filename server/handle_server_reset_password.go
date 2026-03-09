package server

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/Azure/go-autorest/autorest/to"
	"pkg.rbrt.fr/vow/internal/helpers"
	"pkg.rbrt.fr/vow/models"
	"golang.org/x/crypto/bcrypt"
)

type ComAtprotoServerResetPasswordRequest struct {
	Token    string `json:"token" validate:"required"`
	Password string `json:"password" validate:"required"`
}

func (s *Server) handleServerResetPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := s.logger.With("name", "handleServerResetPassword")

	urepo, _ := getContextValue[*models.RepoActor](r, contextKeyRepo)

	var req ComAtprotoServerResetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Error("error decoding", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	if err := s.validator.Struct(req); err != nil {
		helpers.InputError(w, nil)
		return
	}

	if urepo.PasswordResetCode == nil || urepo.PasswordResetCodeExpiresAt == nil {
		helpers.InputError(w, to.StringPtr("InvalidToken"))
		return
	}

	if *urepo.PasswordResetCode != req.Token {
		helpers.InvalidTokenError(w)
		return
	}

	if time.Now().UTC().After(*urepo.PasswordResetCodeExpiresAt) {
		helpers.ExpiredTokenError(w)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), 10)
	if err != nil {
		logger.Error("error creating hash", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	if err := s.db.Exec(ctx, "UPDATE repos SET password_reset_code = NULL, password_reset_code_expires_at = NULL, password = ? WHERE did = ?", nil, hash, urepo.Repo.Did).Error; err != nil {
		logger.Error("error updating repo", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	w.WriteHeader(http.StatusOK)
}
