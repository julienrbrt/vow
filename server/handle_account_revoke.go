package server

import (
	"net/http"

	"github.com/haileyok/cocoon/internal/helpers"
)

type AccountRevokeInput struct {
	Token string `form:"token"`
}

func (s *Server) handleAccountRevoke(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := s.logger.With("name", "handleAccountRevoke")

	if err := r.ParseForm(); err != nil {
		logger.Error("could not parse account revoke form", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	req := AccountRevokeInput{
		Token: r.FormValue("token"),
	}

	repo, sess, err := s.getSessionRepoOrErr(r)
	if err != nil {
		http.Redirect(w, r, "/account/signin", 303)
		return
	}

	if err := s.db.Exec(ctx, "DELETE FROM oauth_tokens WHERE sub = ? AND token = ?", nil, repo.Repo.Did, req.Token).Error; err != nil {
		logger.Error("couldnt delete oauth session for account", "did", repo.Repo.Did, "token", req.Token, "error", err)
		sess.AddFlash("Unable to revoke session. See server logs for more details.", "error")
		sess.Save(r, w)
		http.Redirect(w, r, "/account", 303)
		return
	}

	sess.AddFlash("Session successfully revoked!", "success")
	sess.Save(r, w)
	http.Redirect(w, r, "/account", 303)
}
