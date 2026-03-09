package server

import (
	"net/http"

	"github.com/gorilla/sessions"
)

func (s *Server) handleAccountSignout(w http.ResponseWriter, r *http.Request) {
	sess, err := s.sessions.Get(r, s.config.SessionCookieKey)
	if err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}

	sess.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	}

	sess.Values = map[any]any{}

	if err := sess.Save(r, w); err != nil {
		http.Error(w, "session save error", http.StatusInternalServerError)
		return
	}

	reqUri := r.URL.Query().Get("request_uri")

	redirect := "/account/signin"
	if reqUri != "" {
		redirect += "?" + r.URL.Query().Encode()
	}

	http.Redirect(w, r, redirect, http.StatusSeeOther)
}
