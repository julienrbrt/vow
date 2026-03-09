package server

import "net/http"

type OauthJwksResponse struct {
	Keys []any `json:"keys"`
}

// TODO: ?
func (s *Server) handleOauthJwks(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, 200, OauthJwksResponse{Keys: []any{}})
}
