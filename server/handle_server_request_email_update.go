package server

import (
	"fmt"
	"net/http"
	"time"

	"pkg.rbrt.fr/vow/internal/helpers"
	"pkg.rbrt.fr/vow/models"
)

type ComAtprotoRequestEmailUpdateResponse struct {
	TokenRequired bool `json:"tokenRequired"`
}

func (s *Server) handleServerRequestEmailUpdate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := s.logger.With("name", "handleServerRequestEmailUpdate")

	urepo, _ := getContextValue[*models.RepoActor](r, contextKeyRepo)

	if urepo.EmailConfirmedAt != nil {
		code := fmt.Sprintf("%s-%s", helpers.RandomVarchar(5), helpers.RandomVarchar(5))
		eat := time.Now().Add(10 * time.Minute).UTC()

		if err := s.db.Exec(ctx, "UPDATE repos SET email_update_code = ?, email_update_code_expires_at = ? WHERE did = ?", nil, code, eat, urepo.Repo.Did).Error; err != nil {
			logger.Error("error updating repo", "error", err)
			helpers.ServerError(w, nil)
			return
		}

		if err := s.sendEmailUpdate(urepo.Email, urepo.Handle, code); err != nil {
			logger.Error("error sending email", "error", err)
			helpers.ServerError(w, nil)
			return
		}
	}

	s.writeJSON(w, 200, ComAtprotoRequestEmailUpdateResponse{
		TokenRequired: urepo.EmailConfirmedAt != nil,
	})
}
