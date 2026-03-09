package server

import (
	"encoding/json"
	"net/http"

	"github.com/haileyok/cocoon/models"
)

// This is kinda lame. Not great to implement app.bsky in the pds, but alas

func (s *Server) handleActorPutPreferences(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	repo, _ := getContextValue[*models.RepoActor](r, contextKeyRepo)

	var prefs map[string]any
	if err := json.NewDecoder(r.Body).Decode(&prefs); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	b, err := json.Marshal(prefs)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := s.db.Exec(ctx, "UPDATE repos SET preferences = ? WHERE did = ?", nil, b, repo.Repo.Did).Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}
