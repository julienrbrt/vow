package server

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/gorilla/sessions"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type OauthSigninInput struct {
	Username        string `form:"username"`
	Password        string `form:"password"`
	AuthFactorToken string `form:"token"`
	QueryParams     string `form:"query_params"`
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

func getFlashesFromSession(w http.ResponseWriter, r *http.Request, sess *sessions.Session) map[string]any {
	defer sess.Save(r, w)
	return map[string]any{
		"errors":        sess.Flashes("error"),
		"successes":     sess.Flashes("success"),
		"tokenrequired": sess.Flashes("tokenrequired"),
	}
}

func (s *Server) handleAccountSigninGet(w http.ResponseWriter, r *http.Request) {
	_, sess, err := s.getSessionRepoOrErr(r)
	if err == nil {
		http.Redirect(w, r, "/account", 303)
		return
	}

	s.renderTemplate(w, "signin.html", map[string]any{
		"flashes":     getFlashesFromSession(w, r, sess),
		"QueryParams": r.URL.Query().Encode(),
	})
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
		Username:        r.FormValue("username"),
		Password:        r.FormValue("password"),
		AuthFactorToken: r.FormValue("token"),
		QueryParams:     r.FormValue("query_params"),
	}

	sess, _ := s.sessions.Get(r, s.config.SessionCookieKey)

	req.Username = strings.ToLower(req.Username)
	var idtype string
	if _, err := syntax.ParseDID(req.Username); err == nil {
		idtype = "did"
	} else if _, err := syntax.ParseHandle(req.Username); err == nil {
		idtype = "handle"
	} else {
		idtype = "email"
	}

	queryParams := ""
	if req.QueryParams != "" {
		queryParams = fmt.Sprintf("?%s", req.QueryParams)
	}

	// TODO: we should make this a helper since we do it for the base create_session as well
	var repo models.RepoActor
	var err error
	switch idtype {
	case "did":
		err = s.db.Raw(ctx, "SELECT r.*, a.* FROM repos r LEFT JOIN actors a ON r.did = a.did WHERE r.did = ?", nil, req.Username).Scan(&repo).Error
	case "handle":
		err = s.db.Raw(ctx, "SELECT r.*, a.* FROM actors a LEFT JOIN repos r ON a.did = r.did WHERE a.handle = ?", nil, req.Username).Scan(&repo).Error
	case "email":
		err = s.db.Raw(ctx, "SELECT r.*, a.* FROM repos r LEFT JOIN actors a ON r.did = a.did WHERE r.email = ?", nil, req.Username).Scan(&repo).Error
	}
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			sess.AddFlash("Handle or password is incorrect", "error")
		} else {
			sess.AddFlash("Something went wrong!", "error")
		}
		sess.Save(r, w)
		http.Redirect(w, r, "/account/signin"+queryParams, 303)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(repo.Password), []byte(req.Password)); err != nil {
		if err != bcrypt.ErrMismatchedHashAndPassword {
			sess.AddFlash("Handle or password is incorrect", "error")
		} else {
			sess.AddFlash("Something went wrong!", "error")
		}
		sess.Save(r, w)
		http.Redirect(w, r, "/account/signin"+queryParams, 303)
		return
	}

	// if repo requires 2FA token and one hasn't been provided, return error prompting for one
	if repo.TwoFactorType != models.TwoFactorTypeNone && req.AuthFactorToken == "" {
		err = s.createAndSendTwoFactorCode(ctx, repo)
		if err != nil {
			sess.AddFlash("Something went wrong!", "error")
			sess.Save(r, w)
			http.Redirect(w, r, "/account/signin"+queryParams, 303)
			return
		}

		sess.AddFlash("requires 2FA token", "tokenrequired")
		sess.Save(r, w)
		http.Redirect(w, r, "/account/signin"+queryParams, 303)
		return
	}

	// if 2FA is required, now check that the one provided is valid
	if repo.TwoFactorType != models.TwoFactorTypeNone {
		if repo.TwoFactorCode == nil || repo.TwoFactorCodeExpiresAt == nil {
			err = s.createAndSendTwoFactorCode(ctx, repo)
			if err != nil {
				sess.AddFlash("Something went wrong!", "error")
				sess.Save(r, w)
				http.Redirect(w, r, "/account/signin"+queryParams, 303)
				return
			}

			sess.AddFlash("requires 2FA token", "tokenrequired")
			sess.Save(r, w)
			http.Redirect(w, r, "/account/signin"+queryParams, 303)
			return
		}

		if *repo.TwoFactorCode != req.AuthFactorToken {
			helpers.InvalidTokenError(w)
			return
		}

		if time.Now().UTC().After(*repo.TwoFactorCodeExpiresAt) {
			helpers.ExpiredTokenError(w)
			return
		}
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
		http.Redirect(w, r, "/oauth/authorize"+queryParams, 303)
	} else {
		http.Redirect(w, r, "/account", 303)
	}
}
