package server

import (
	"net/http"
	"time"

	"github.com/bluesky-social/indigo/util"
	"github.com/haileyok/cocoon/models"
)

func (s *Server) handleAgeAssurance(w http.ResponseWriter, r *http.Request) {
	repo, _ := getContextValue[*models.RepoActor](r, contextKeyRepo)

	resp := map[string]any{
		"state": map[string]any{
			"status":          "assured",
			"access":          "full",
			"lastInitiatedAt": time.Now().Format(util.ISO8601),
		},
		"metadata": map[string]any{
			"accountCreatedAt": repo.CreatedAt.Format(util.ISO8601),
		},
	}

	s.writeJSON(w, 200, resp)
}
