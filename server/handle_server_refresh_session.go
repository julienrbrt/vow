package server

import (
	"net/http"

	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
)

type ComAtprotoServerRefreshSessionResponse struct {
	AccessJwt  string  `json:"accessJwt"`
	RefreshJwt string  `json:"refreshJwt"`
	Handle     string  `json:"handle"`
	Did        string  `json:"did"`
	Active     bool    `json:"active"`
	Status     *string `json:"status,omitempty"`
}

func (s *Server) handleRefreshSession(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := s.logger.With("name", "handleServerRefreshSession")

	token, _ := getContextValue[string](r, contextKeyToken)
	repo, _ := getContextValue[*models.RepoActor](r, contextKeyRepo)

	if err := s.db.Exec(ctx, "DELETE FROM refresh_tokens WHERE token = ?", nil, token).Error; err != nil {
		logger.Error("error getting refresh token from db", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	if err := s.db.Exec(ctx, "DELETE FROM tokens WHERE refresh_token = ?", nil, token).Error; err != nil {
		logger.Error("error deleting access token from db", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	sess, err := s.createSession(ctx, &repo.Repo)
	if err != nil {
		logger.Error("error creating new session for refresh", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	s.writeJSON(w, 200, ComAtprotoServerRefreshSessionResponse{
		AccessJwt:  sess.AccessToken,
		RefreshJwt: sess.RefreshToken,
		Handle:     repo.Handle,
		Did:        repo.Repo.Did,
		Active:     repo.Active(),
		Status:     repo.Status(),
	})
}
