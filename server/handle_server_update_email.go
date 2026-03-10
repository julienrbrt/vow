package server

import (
	"encoding/json"
	"net/http"
	"time"

	"pkg.rbrt.fr/vow/internal/helpers"
	"pkg.rbrt.fr/vow/models"
)

type ComAtprotoServerUpdateEmailRequest struct {
	Email string `json:"email" validate:"required"`
	Token string `json:"token"`
}

func (s *Server) handleServerUpdateEmail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := s.logger.With("name", "handleServerUpdateEmail")

	urepo, _ := getContextValue[*models.RepoActor](r, contextKeyRepo)

	var req ComAtprotoServerUpdateEmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Error("error decoding", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	if err := s.validator.Struct(req); err != nil {
		helpers.InputError(w, nil)
		return
	}

	if req.Token != "" {
		if urepo.EmailUpdateCode == nil || urepo.EmailUpdateCodeExpiresAt == nil {
			helpers.InvalidTokenError(w)
			return
		}

		if *urepo.EmailUpdateCode != req.Token {
			helpers.InvalidTokenError(w)
			return
		}

		if time.Now().UTC().After(*urepo.EmailUpdateCodeExpiresAt) {
			helpers.ExpiredTokenError(w)
			return
		}
	}

	query := "UPDATE repos SET email_update_code = NULL, email_update_code_expires_at = NULL, email = ?"

	if urepo.Email != req.Email {
		query += ", email_confirmed_at = NULL"
	}

	query += " WHERE did = ?"

	if err := s.db.Exec(ctx, query, nil, req.Email, urepo.Repo.Did).Error; err != nil {
		logger.Error("error updating repo", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	w.WriteHeader(http.StatusOK)
}
