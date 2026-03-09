package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/bluesky-social/indigo/api/atproto"
	"github.com/bluesky-social/indigo/atproto/atcrypto"
	atp "github.com/bluesky-social/indigo/atproto/repo"
	"github.com/bluesky-social/indigo/atproto/repo/mst"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/bluesky-social/indigo/events"
	"github.com/bluesky-social/indigo/util"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"pkg.rbrt.fr/vow/internal/helpers"
	"pkg.rbrt.fr/vow/models"
)

type ComAtprotoServerCreateAccountRequest struct {
	Email      string  `json:"email" validate:"required,email"`
	Handle     string  `json:"handle" validate:"required,atproto-handle"`
	Did        *string `json:"did" validate:"atproto-did"`
	Password   string  `json:"password" validate:"required"`
	InviteCode string  `json:"inviteCode" validate:"omitempty"`
}

type ComAtprotoServerCreateAccountResponse struct {
	AccessJwt  string `json:"accessJwt"`
	RefreshJwt string `json:"refreshJwt"`
	Handle     string `json:"handle"`
	Did        string `json:"did"`
}

func (s *Server) handleCreateAccount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := s.logger.With("name", "handleServerCreateAccount")

	var request ComAtprotoServerCreateAccountRequest

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		logger.Error("error receiving request", "endpoint", "com.atproto.server.createAccount", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	request.Handle = strings.ToLower(request.Handle)

	if err := s.validator.Struct(request); err != nil {
		logger.Error("error validating request", "endpoint", "com.atproto.server.createAccount", "error", err)

		var verr ValidationError
		if errors.As(err, &verr) {
			if verr.Field == "Email" {
				helpers.InputError(w, to.StringPtr("InvalidEmail"))
				return
			}

			if verr.Field == "Handle" {
				helpers.InputError(w, to.StringPtr("InvalidHandle"))
				return
			}

			if verr.Field == "Password" {
				helpers.InputError(w, to.StringPtr("InvalidPassword"))
				return
			}

			if verr.Field == "InviteCode" {
				helpers.InputError(w, to.StringPtr("InvalidInviteCode"))
				return
			}
		}
	}

	var signupDid string
	if request.Did != nil {
		signupDid = *request.Did

		token := strings.TrimSpace(strings.Replace(r.Header.Get("authorization"), "Bearer ", "", 1))
		if token == "" {
			helpers.UnauthorizedError(w, to.StringPtr("must authenticate to use an existing did"))
			return
		}
		authDid, err := s.validateServiceAuth(r.Context(), token, "com.atproto.server.createAccount")

		if err != nil {
			logger.Warn("error validating authorization token", "endpoint", "com.atproto.server.createAccount", "error", err)
			helpers.UnauthorizedError(w, to.StringPtr("invalid authorization token"))
			return
		}

		if authDid != signupDid {
			helpers.ForbiddenError(w, to.StringPtr("auth did did not match signup did"))
			return
		}
	}

	// see if the handle is already taken
	actor, err := s.getActorByHandle(ctx, request.Handle)
	if err != nil && err != gorm.ErrRecordNotFound {
		logger.Error("error looking up handle in db", "endpoint", "com.atproto.server.createAccount", "error", err)
		helpers.ServerError(w, nil)
		return
	}
	if err == nil && actor.Did != signupDid {
		helpers.InputError(w, to.StringPtr("HandleNotAvailable"))
		return
	}

	if did, err := s.passport.ResolveHandle(r.Context(), request.Handle); err == nil && did != signupDid {
		helpers.InputError(w, to.StringPtr("HandleNotAvailable"))
		return
	}

	var ic models.InviteCode
	if s.config.RequireInvite {
		if strings.TrimSpace(request.InviteCode) == "" {
			helpers.InputError(w, to.StringPtr("InvalidInviteCode"))
			return
		}

		if err := s.db.Raw(ctx, "SELECT * FROM invite_codes WHERE code = ?", nil, request.InviteCode).Scan(&ic).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				helpers.InputError(w, to.StringPtr("InvalidInviteCode"))
				return
			}
			logger.Error("error getting invite code from db", "error", err)
			helpers.ServerError(w, nil)
			return
		}

		if ic.RemainingUseCount < 1 {
			helpers.InputError(w, to.StringPtr("InvalidInviteCode"))
			return
		}
	}

	// see if the email is already taken
	existingRepo, err := s.getRepoByEmail(ctx, request.Email)
	if err != nil && err != gorm.ErrRecordNotFound {
		logger.Error("error looking up email in db", "endpoint", "com.atproto.server.createAccount", "error", err)
		helpers.ServerError(w, nil)
		return
	}
	if err == nil && existingRepo.Did != signupDid {
		helpers.InputError(w, to.StringPtr("EmailNotAvailable"))
		return
	}

	// TODO: unsupported domains

	var k *atcrypto.PrivateKeyK256

	if signupDid != "" {
		reservedKey, err := s.getReservedKey(ctx, signupDid)
		if err != nil {
			logger.Error("error looking up reserved key", "error", err)
		}
		if reservedKey != nil {
			k, err = atcrypto.ParsePrivateBytesK256(reservedKey.PrivateKey)
			if err != nil {
				logger.Error("error parsing reserved key", "error", err)
				k = nil
			} else {
				defer func() {
					if delErr := s.deleteReservedKey(ctx, reservedKey.KeyDid, reservedKey.Did); delErr != nil {
						logger.Error("error deleting reserved key", "error", delErr)
					}
				}()
			}
		}
	}

	if k == nil {
		k, err = atcrypto.GeneratePrivateKeyK256()
		if err != nil {
			logger.Error("error creating signing key", "endpoint", "com.atproto.server.createAccount", "error", err)
			helpers.ServerError(w, nil)
			return
		}
	}

	if signupDid == "" {
		did, op, err := s.plcClient.CreateDID(k, "", request.Handle)
		if err != nil {
			logger.Error("error creating operation", "endpoint", "com.atproto.server.createAccount", "error", err)
			helpers.ServerError(w, nil)
			return
		}

		if err := s.plcClient.SendOperation(r.Context(), did, op); err != nil {
			logger.Error("error sending plc op", "endpoint", "com.atproto.server.createAccount", "error", err)
			helpers.ServerError(w, nil)
			return
		}
		signupDid = did
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(request.Password), 10)
	if err != nil {
		logger.Error("error hashing password", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	urepo := models.Repo{
		Did:                   signupDid,
		CreatedAt:             time.Now(),
		Email:                 request.Email,
		EmailVerificationCode: to.StringPtr(fmt.Sprintf("%s-%s", helpers.RandomVarchar(6), helpers.RandomVarchar(6))),
		Password:              string(hashed),
		SigningKey:            k.Bytes(),
	}

	if actor == nil {
		actor = &models.Actor{
			Did:    signupDid,
			Handle: request.Handle,
		}

		if err := s.db.Create(ctx, &urepo, nil).Error; err != nil {
			logger.Error("error inserting new repo", "error", err)
			helpers.ServerError(w, nil)
			return
		}

		if err := s.db.Create(ctx, &actor, nil).Error; err != nil {
			logger.Error("error inserting new actor", "error", err)
			helpers.ServerError(w, nil)
			return
		}
	} else {
		if err := s.db.Save(ctx, &actor, nil).Error; err != nil {
			logger.Error("error inserting new actor", "error", err)
			helpers.ServerError(w, nil)
			return
		}
	}

	if request.Did == nil || *request.Did == "" {
		bs := s.getBlockstore(signupDid)

		clk := syntax.NewTIDClock(0)
		r := &atp.Repo{
			DID:         syntax.DID(signupDid),
			Clock:       clk,
			MST:         mst.NewEmptyTree(),
			RecordStore: bs,
		}

		root, rev, err := commitRepo(context.TODO(), bs, r, urepo.SigningKey)
		if err != nil {
			logger.Error("error committing", "error", err)
			helpers.ServerError(w, nil)
			return
		}

		if err := s.UpdateRepo(context.TODO(), urepo.Did, root, rev); err != nil {
			logger.Error("error updating repo after commit", "error", err)
			helpers.ServerError(w, nil)
			return
		}

		if err := s.evtman.AddEvent(context.TODO(), &events.XRPCStreamEvent{
			RepoIdentity: &atproto.SyncSubscribeRepos_Identity{
				Did:    urepo.Did,
				Handle: to.StringPtr(request.Handle),
				Seq:    time.Now().UnixMicro(), // TODO: no
				Time:   time.Now().Format(util.ISO8601),
			},
		}); err != nil {
			logger.Error("failed to add event", "error", err)
		}
	}

	if s.config.RequireInvite {
		if err := s.db.Raw(ctx, "UPDATE invite_codes SET remaining_use_count = remaining_use_count - 1 WHERE code = ?", nil, request.InviteCode).Scan(&ic).Error; err != nil {
			logger.Error("error decrementing use count", "error", err)
			helpers.ServerError(w, nil)
			return
		}
	}

	sess, err := s.createSession(ctx, &urepo)
	if err != nil {
		logger.Error("error creating new session", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	go func() {
		if err := s.sendEmailVerification(urepo.Email, actor.Handle, *urepo.EmailVerificationCode); err != nil {
			logger.Error("error sending email verification email", "error", err)
		}
		if err := s.sendWelcomeMail(urepo.Email, actor.Handle); err != nil {
			logger.Error("error sending welcome email", "error", err)
		}
	}()

	s.writeJSON(w, 200, ComAtprotoServerCreateAccountResponse{
		AccessJwt:  sess.AccessToken,
		RefreshJwt: sess.RefreshToken,
		Handle:     request.Handle,
		Did:        signupDid,
	})
}
