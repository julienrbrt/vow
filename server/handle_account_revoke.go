package server

import (
	"net/http"

	"pkg.rbrt.fr/vow/internal/helpers"
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
		http.Redirect(w, r, "/account/signin", http.StatusSeeOther)
		return
	}

	if err := s.db.Exec(ctx, "DELETE FROM oauth_tokens WHERE sub = ? AND token = ?", nil, repo.Repo.Did, req.Token).Error; err != nil {
		logger.Error("couldnt delete oauth session for account", "did", repo.Repo.Did, "token", req.Token, "error", err)
		sess.AddFlash("Unable to revoke session. See server logs for more details.", "error")
		if err := sess.Save(r, w); err != nil {
			logger.Error("failed to save session", "error", err)
		}
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}

	sess.AddFlash("Session successfully revoked!", "success")
	if err := sess.Save(r, w); err != nil {
		logger.Error("failed to save session", "error", err)
	}
	http.Redirect(w, r, "/account", http.StatusSeeOther)
}
