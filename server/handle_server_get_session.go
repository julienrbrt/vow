package server

import (
	"net/http"

	"github.com/haileyok/cocoon/models"
)

type ComAtprotoServerGetSessionResponse struct {
	Handle          string  `json:"handle"`
	Did             string  `json:"did"`
	Email           string  `json:"email"`
	EmailConfirmed  bool    `json:"emailConfirmed"`
	EmailAuthFactor bool    `json:"emailAuthFactor"`
	Active          bool    `json:"active"`
	Status          *string `json:"status,omitempty"`
}

func (s *Server) handleGetSession(w http.ResponseWriter, r *http.Request) {
	repo, _ := getContextValue[*models.RepoActor](r, contextKeyRepo)

	s.writeJSON(w, 200, ComAtprotoServerGetSessionResponse{
		Handle:          repo.Handle,
		Did:             repo.Repo.Did,
		Email:           repo.Email,
		EmailConfirmed:  repo.EmailConfirmedAt != nil,
		EmailAuthFactor: repo.TwoFactorType != models.TwoFactorTypeNone,
		Active:          repo.Active(),
		Status:          repo.Status(),
	})
}
