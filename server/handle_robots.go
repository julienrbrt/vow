package server

import (
	"fmt"
	"net/http"
)

func (s *Server) handleRobots(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	_, _ = fmt.Fprint(w, "# Beep boop beep boop\n\n# Crawl me 🥺\nUser-agent: *\nAllow: /")
}
