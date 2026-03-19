package server

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"pkg.rbrt.fr/vow/internal/helpers"
	"pkg.rbrt.fr/vow/models"
)

type OauthSigninInput struct {
	Username    string `form:"username"`
	Password    string `form:"password"`
	QueryParams string `form:"query_params"`
}

func (s *Server) getSessionRepoOrErr(r *http.Request) (*models.RepoActor, *sessions.Session, error) {
	ctx := r.Context()

	sess, err := s.sessions.Get(r, s.config.SessionCookieKey)
	if err != nil {
		return nil, nil, err
	}

	did, ok := sess.Values["did"].(string)
	if !ok {
		return nil, sess, errors.New("did was not set in session")
	}

	repo, err := s.getRepoActorByDid(ctx, did)
	if err != nil {
		return nil, sess, err
	}

	return repo, sess, nil
}

func (s *Server) getFlashesFromSession(w http.ResponseWriter, r *http.Request, sess *sessions.Session) map[string]any {
	defer func() {
		if err := sess.Save(r, w); err != nil {
			s.logger.Error("failed to save session", "error", err)
		}
	}()
	return map[string]any{
		"errors":    sess.Flashes("error"),
		"successes": sess.Flashes("success"),
	}
}

func (s *Server) handleAccountSigninGet(w http.ResponseWriter, r *http.Request) {
	_, sess, err := s.getSessionRepoOrErr(r)
	if err == nil {
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}

	if err := s.renderTemplate(w, "signin.html", map[string]any{
		"flashes":     s.getFlashesFromSession(w, r, sess),
		"QueryParams": r.URL.Query().Encode(),
	}); err != nil {
		s.logger.Error("failed to render template", "error", err)
	}
}

func (s *Server) handleAccountSigninPost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := s.logger.With("name", "handleAccountSigninPost")

	if err := r.ParseForm(); err != nil {
		logger.Error("error parsing sign in form", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	req := OauthSigninInput{
		Username:    r.FormValue("username"),
		Password:    r.FormValue("password"),
		QueryParams: r.FormValue("query_params"),
	}

	sess, _ := s.sessions.Get(r, s.config.SessionCookieKey)

	req.Username = strings.ToLower(req.Username)

	queryParams := ""
	if req.QueryParams != "" {
		queryParams = fmt.Sprintf("?%s", req.QueryParams)
	}

	// lookup the account by did, handle or email
	repo, err := s.getRepoActorByIdentifier(ctx, req.Username)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			sess.AddFlash("Handle or password is incorrect", "error")
		} else {
			sess.AddFlash("Something went wrong!", "error")
		}
		if err := sess.Save(r, w); err != nil {
			logger.Error("failed to save session", "error", err)
		}
		http.Redirect(w, r, "/account/signin"+queryParams, http.StatusSeeOther)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(repo.Password), []byte(req.Password)); err != nil {
		if err != bcrypt.ErrMismatchedHashAndPassword {
			sess.AddFlash("Handle or password is incorrect", "error")
		} else {
			sess.AddFlash("Something went wrong!", "error")
		}
		if err := sess.Save(r, w); err != nil {
			logger.Error("failed to save session", "error", err)
		}
		http.Redirect(w, r, "/account/signin"+queryParams, http.StatusSeeOther)
		return
	}

	sess.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   int(AccountSessionMaxAge.Seconds()),
		HttpOnly: true,
	}

	sess.Values = map[any]any{}
	sess.Values["did"] = repo.Repo.Did

	if err := sess.Save(r, w); err != nil {
		helpers.ServerError(w, nil)
		return
	}

	if queryParams != "" {
		http.Redirect(w, r, "/oauth/authorize"+queryParams, http.StatusSeeOther)
	} else {
		http.Redirect(w, r, "/account", http.StatusSeeOther)
	}
}
