package server

import (
	"encoding/json"
	"net/http"
)

type updateCompatRequest struct {
	Compat bool `json:"compat"`
}

func (s *Server) handleAccountUpdateCompat(w http.ResponseWriter, r *http.Request) {
	logger := s.logger.With("name", "handleAccountUpdateCompat")

	var req updateCompatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_request", "message": "Invalid JSON body"})
		return
	}

	repo, _, err := s.getSessionRepoOrErr(r)
	if err != nil {
		s.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	if err := s.db.Exec(r.Context(), "UPDATE repos SET compat_mode = ? WHERE did = ?", nil, req.Compat, repo.Repo.Did).Error; err != nil {
		logger.Error("failed to update compat mode", "error", err, "did", repo.Repo.Did)
		s.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}

	logger.Info("updated compat mode", "did", repo.Repo.Did, "compat", req.Compat)
	s.writeJSON(w, http.StatusOK, map[string]any{"success": true, "compat": req.Compat})
}
