package server

import (
	"fmt"
	"net/http"
	"time"

	"pkg.rbrt.fr/vow/internal/helpers"
	"pkg.rbrt.fr/vow/models"
)

func (s *Server) handleServerRequestAccountDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := s.logger.With("name", "handleServerRequestAccountDelete")

	urepo, _ := getContextValue[*models.RepoActor](r, contextKeyRepo)

	token := fmt.Sprintf("%s-%s", helpers.RandomVarchar(5), helpers.RandomVarchar(5))
	expiresAt := time.Now().UTC().Add(15 * time.Minute)

	if err := s.db.Exec(ctx, "UPDATE repos SET account_delete_code = ?, account_delete_code_expires_at = ? WHERE did = ?", nil, token, expiresAt, urepo.Repo.Did).Error; err != nil {
		logger.Error("error setting deletion token", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	if urepo.Email != "" {
		if err := s.sendAccountDeleteEmail(urepo.Email, urepo.Actor.Handle, token); err != nil {
			logger.Error("error sending account deletion email", "error", err)
		}
	}

	w.WriteHeader(http.StatusOK)
}

func (s *Server) sendAccountDeleteEmail(email, handle, token string) error {
	if s.mail == nil {
		return nil
	}

	s.mailLk.Lock()
	defer s.mailLk.Unlock()

	s.mail.To(email)
	s.mail.Subject("Account Deletion Request for " + s.config.Hostname)
	s.mail.Plain().Set(fmt.Sprintf("Hello %s. Your account deletion code is %s. This code will expire in fifteen minutes. If you did not request this, please ignore this email.", handle, token))

	if err := s.mail.Send(); err != nil {
		return err
	}

	return nil
}
