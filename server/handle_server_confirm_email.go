package server

import (
	"encoding/json"
	"net/http"
	"time"

	"pkg.rbrt.fr/vow/internal/helpers"
	"pkg.rbrt.fr/vow/models"
)

type ComAtprotoServerConfirmEmailRequest struct {
	Email string `json:"email" validate:"required"`
	Token string `json:"token" validate:"required"`
}

func (s *Server) handleServerConfirmEmail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := s.logger.With("name", "handleServerConfirmEmail")

	urepo, _ := getContextValue[*models.RepoActor](r, contextKeyRepo)

	var req ComAtprotoServerConfirmEmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Error("error decoding", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	if err := s.validator.Struct(req); err != nil {
		helpers.InputError(w, nil)
		return
	}

	if urepo.EmailVerificationCode == nil || urepo.EmailVerificationCodeExpiresAt == nil {
		helpers.ExpiredTokenError(w)
		return
	}

	if *urepo.EmailVerificationCode != req.Token {
		helpers.InputError(w, new("InvalidToken"))
		return
	}

	if time.Now().UTC().After(*urepo.EmailVerificationCodeExpiresAt) {
		helpers.ExpiredTokenError(w)
		return
	}

	now := time.Now().UTC()

	if err := s.db.Exec(ctx, "UPDATE repos SET email_verification_code = NULL, email_verification_code_expires_at = NULL, email_confirmed_at = ? WHERE did = ?", nil, now, urepo.Repo.Did).Error; err != nil {
		logger.Error("error updating user", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	w.WriteHeader(http.StatusOK)
}
