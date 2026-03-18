package server

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/bluesky-social/indigo/api/atproto"
	atp "github.com/bluesky-social/indigo/atproto/repo"
	"github.com/bluesky-social/indigo/atproto/repo/mst"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/bluesky-social/indigo/events"
	"github.com/bluesky-social/indigo/util"
	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"pkg.rbrt.fr/vow/internal/helpers"
	"pkg.rbrt.fr/vow/models"
)

// handleAccountSignupGet renders the sign-up form.
func (s *Server) handleAccountSignupGet(w http.ResponseWriter, r *http.Request) {
	_, sess, err := s.getSessionRepoOrErr(r)
	if err == nil {
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}

	if sess == nil {
		sess, _ = s.sessions.Get(r, s.config.SessionCookieKey)
	}

	s.renderSignupForm(w, r, sess, "", "", "")
}

// handleAccountSignupPost creates an account from the sign-up form.
func (s *Server) handleAccountSignupPost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := s.logger.With("name", "handleAccountSignupPost")

	if err := r.ParseForm(); err != nil {
		logger.Error("error parsing sign up form", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	handle := strings.TrimSpace(r.FormValue("handle"))
	email := strings.TrimSpace(r.FormValue("email"))
	password := r.FormValue("password")
	inviteCode := strings.TrimSpace(r.FormValue("invite_code"))
	queryParams := r.FormValue("query_params")

	sess, _ := s.sessions.Get(r, s.config.SessionCookieKey)

	fail := func(msg string) {
		sess.AddFlash(msg, "error")
		if err := sess.Save(r, w); err != nil {
			logger.Error("failed to save session", "error", err)
		}
		s.renderSignupForm(w, r, sess, handle, email, inviteCode)
	}

	if handle == "" || email == "" || password == "" {
		fail("All fields are required.")
		return
	}

	// Add the server domain if needed.
	if !strings.Contains(handle, ".") {
		handle = handle + "." + s.config.Hostname
	}
	handle = strings.ToLower(handle)

	// Validate the handle.
	if _, err := syntax.ParseHandle(handle); err != nil {
		fail("Invalid handle. Use only letters, numbers and hyphens.")
		return
	}

	// Ensure the handle is on this server.
	if !strings.HasSuffix(handle, "."+s.config.Hostname) && handle != s.config.Hostname {
		fail("Handle must be under " + s.config.Hostname + ".")
		return
	}

	if len(password) < 6 {
		fail("Password must be at least 6 characters.")
		return
	}

	var ic models.InviteCode
	if s.config.RequireInvite {
		if inviteCode == "" {
			fail("An invite code is required.")
			return
		}

		if err := s.db.Raw(ctx, "SELECT * FROM invite_codes WHERE code = ?", nil, inviteCode).Scan(&ic).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				fail("Invalid invite code.")
				return
			}
			logger.Error("error looking up invite code", "error", err)
			fail("Something went wrong. Please try again.")
			return
		}

		if ic.RemainingUseCount < 1 {
			fail("This invite code has already been used.")
			return
		}
	}

	actor, err := s.getActorByHandle(ctx, handle)
	if err != nil && err != gorm.ErrRecordNotFound {
		logger.Error("error looking up handle", "error", err)
		fail("Something went wrong. Please try again.")
		return
	}
	if err == nil && actor != nil {
		fail("That handle is already taken.")
		return
	}

	if did, err := s.passport.ResolveHandle(r.Context(), handle); err == nil && did != "" {
		fail("That handle is already taken.")
		return
	}

	existingRepo, err := s.getRepoByEmail(ctx, email)
	if err != nil && err != gorm.ErrRecordNotFound {
		logger.Error("error looking up email", "error", err)
		fail("Something went wrong. Please try again.")
		return
	}
	if err == nil && existingRepo.Did != "" {
		fail("That email address is already registered.")
		return
	}

	did, op, err := s.plcClient.CreateDID(s.plcClient.RotationPrivateKey(), "", handle)
	if err != nil {
		logger.Error("error creating PLC DID", "error", err)
		fail("Something went wrong. Please try again.")
		return
	}

	if err := s.plcClient.SendOperation(ctx, did, op); err != nil {
		logger.Error("error sending PLC operation", "error", err)
		fail("Something went wrong. Please try again.")
		return
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		logger.Error("error hashing password", "error", err)
		fail("Something went wrong. Please try again.")
		return
	}

	urepo := models.Repo{
		Did:                   did,
		CreatedAt:             time.Now(),
		Email:                 email,
		EmailVerificationCode: new(fmt.Sprintf("%s-%s", helpers.RandomVarchar(6), helpers.RandomVarchar(6))),
		Password:              string(hashed),
	}

	newActor := &models.Actor{
		Did:    did,
		Handle: handle,
	}

	if err := s.db.Create(ctx, &urepo, nil).Error; err != nil {
		logger.Error("error inserting repo", "error", err)
		fail("Something went wrong. Please try again.")
		return
	}

	if err := s.db.Create(ctx, newActor, nil).Error; err != nil {
		logger.Error("error inserting actor", "error", err)
		fail("Something went wrong. Please try again.")
		return
	}

	bs := newBlockstoreForRepo(did, s.ipfsAPI)

	clk := syntax.NewTIDClock(0)
	repo := &atp.Repo{
		DID:         syntax.DID(did),
		Clock:       clk,
		MST:         mst.NewEmptyTree(),
		RecordStore: bs,
	}

	root, rev, err := commitRepo(ctx, bs, repo, s.plcClient.RotationKeyBytes())
	if err != nil {
		logger.Error("error committing genesis", "error", err)
		fail("Something went wrong. Please try again.")
		return
	}

	if err := s.UpdateRepo(ctx, did, root, rev); err != nil {
		logger.Error("error updating repo after genesis commit", "error", err)
		fail("Something went wrong. Please try again.")
		return
	}

	if err := s.evtman.AddEvent(ctx, &events.XRPCStreamEvent{
		RepoIdentity: &atproto.SyncSubscribeRepos_Identity{
			Did:    did,
			Handle: new(handle),
			Seq:    time.Now().UnixMicro(),
			Time:   time.Now().Format(util.ISO8601),
		},
	}); err != nil {
		logger.Error("failed to add identity event", "error", err)
	}

	if s.config.RequireInvite {
		if err := s.db.Raw(ctx, "UPDATE invite_codes SET remaining_use_count = remaining_use_count - 1 WHERE code = ?", nil, inviteCode).Scan(&ic).Error; err != nil {
			logger.Error("error decrementing invite code use count", "error", err)
		}

		if err := s.db.Create(ctx, &models.InviteCodeUse{
			Code:   inviteCode,
			UsedBy: did,
			UsedAt: time.Now(),
		}, nil).Error; err != nil {
			logger.Error("error recording invite code use", "error", err)
		}
	}

	go func() {
		if err := s.sendEmailVerification(email, handle, *urepo.EmailVerificationCode); err != nil {
			logger.Error("error sending email verification", "error", err)
		}
		if err := s.sendWelcomeMail(email, handle); err != nil {
			logger.Error("error sending welcome email", "error", err)
		}
	}()

	sess.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   int(AccountSessionMaxAge.Seconds()),
		HttpOnly: true,
	}

	sess.Values = map[any]any{}
	sess.Values["did"] = did

	if err := sess.Save(r, w); err != nil {
		logger.Error("failed to save session", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	if queryParams != "" {
		http.Redirect(w, r, "/oauth/authorize?"+queryParams, http.StatusSeeOther)
	} else {
		http.Redirect(w, r, "/account", http.StatusSeeOther)
	}
}

// renderSignupForm renders `signup.html`.
func (s *Server) renderSignupForm(w http.ResponseWriter, r *http.Request, sess *sessions.Session, handle, email, inviteCode string) {
	if err := s.renderTemplate(w, "signup.html", map[string]any{
		"Hostname":       s.config.Hostname,
		"HandleSuffix":   ", e.g. alice." + s.config.Hostname,
		"RequireInvite":  s.config.RequireInvite,
		"FormHandle":     handle,
		"FormEmail":      email,
		"FormInviteCode": inviteCode,
		"QueryParams":    r.URL.Query().Encode(),
		"flashes":        s.getFlashesFromSession(w, r, sess),
	}); err != nil {
		s.logger.Error("failed to render signup template", "error", err)
	}
}
