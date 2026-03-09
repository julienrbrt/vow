package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"pkg.rbrt.fr/vow/internal/helpers"
	"pkg.rbrt.fr/vow/models"
)

type ComAtprotoServerRequestPasswordResetRequest struct {
	Email string `json:"email" validate:"required"`
}

func (s *Server) handleServerRequestPasswordReset(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := s.logger.With("name", "handleServerRequestPasswordReset")

	var urepo *models.RepoActor
	if repo, ok := getContextValue[*models.RepoActor](r, contextKeyRepo); ok {
		urepo = repo
	} else {
		var req ComAtprotoServerRequestPasswordResetRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			helpers.ServerError(w, nil)
			return
		}

		if err := s.validator.Struct(req); err != nil {
			helpers.InputError(w, nil)
			return
		}

		murepo, err := s.getRepoActorByEmail(ctx, req.Email)
		if err != nil {
			helpers.ServerError(w, nil)
			return
		}

		urepo = murepo
	}

	code := fmt.Sprintf("%s-%s", helpers.RandomVarchar(5), helpers.RandomVarchar(5))
	eat := time.Now().Add(10 * time.Minute).UTC()

	if err := s.db.Exec(ctx, "UPDATE repos SET password_reset_code = ?, password_reset_code_expires_at = ? WHERE did = ?", nil, code, eat, urepo.Repo.Did).Error; err != nil {
		logger.Error("error updating repo", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	if err := s.sendPasswordReset(urepo.Email, urepo.Handle, code); err != nil {
		logger.Error("error sending email", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	w.WriteHeader(http.StatusOK)
}
