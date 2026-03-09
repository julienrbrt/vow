package server

import (
	"net/http"

	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
)

func (s *Server) handleDeleteSession(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	token, _ := getContextValue[string](r, contextKeyToken)

	var acctok models.Token
	if err := s.db.Raw(ctx, "DELETE FROM tokens WHERE token = ? RETURNING *", nil, token).Scan(&acctok).Error; err != nil {
		s.logger.Error("error deleting access token from db", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	if err := s.db.Exec(ctx, "DELETE FROM refresh_tokens WHERE token = ?", nil, acctok.RefreshToken).Error; err != nil {
		s.logger.Error("error deleting refresh token from db", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	w.WriteHeader(http.StatusOK)
}
