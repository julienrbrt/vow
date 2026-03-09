package server

import "net/http"

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, 200, map[string]string{
		"version": "cocoon " + s.config.Version,
	})
}
