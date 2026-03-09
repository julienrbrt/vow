package server

import (
	"encoding/json"
	"net/http"

	"github.com/haileyok/cocoon/models"
)

// This is kinda lame. Not great to implement app.bsky in the pds, but alas

func (s *Server) handleActorGetPreferences(w http.ResponseWriter, r *http.Request) {
	repo, _ := getContextValue[*models.RepoActor](r, contextKeyRepo)

	var prefs map[string]any
	err := json.Unmarshal(repo.Preferences, &prefs)
	if err != nil || prefs["preferences"] == nil {
		prefs = map[string]any{
			"preferences": []any{},
		}
	}

	s.writeJSON(w, 200, prefs)
}
