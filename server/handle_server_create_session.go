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
	"github.com/bluesky-social/indigo/atproto/syntax"
	"pkg.rbrt.fr/vow/internal/helpers"
	"pkg.rbrt.fr/vow/models"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type ComAtprotoServerCreateSessionRequest struct {
	Identifier      string  `json:"identifier" validate:"required"`
	Password        string  `json:"password" validate:"required"`
	AuthFactorToken *string `json:"authFactorToken,omitempty"`
}

type ComAtprotoServerCreateSessionResponse struct {
	AccessJwt       string  `json:"accessJwt"`
	RefreshJwt      string  `json:"refreshJwt"`
	Handle          string  `json:"handle"`
	Did             string  `json:"did"`
	Email           string  `json:"email"`
	EmailConfirmed  bool    `json:"emailConfirmed"`
	EmailAuthFactor bool    `json:"emailAuthFactor"`
	Active          bool    `json:"active"`
	Status          *string `json:"status,omitempty"`
}

func (s *Server) handleCreateSession(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := s.logger.With("name", "handleServerCreateSession")

	var req ComAtprotoServerCreateSessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Error("error decoding request", "endpoint", "com.atproto.server.serverCreateSession", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	if err := s.validator.Struct(req); err != nil {
		var verr ValidationError
		if errors.As(err, &verr) {
			if verr.Field == "Identifier" {
				helpers.InputError(w, to.StringPtr("InvalidRequest"))
				return
			}

			if verr.Field == "Password" {
				helpers.InputError(w, to.StringPtr("InvalidRequest"))
				return
			}
		}
	}

	req.Identifier = strings.ToLower(req.Identifier)
	var idtype string
	if _, err := syntax.ParseDID(req.Identifier); err == nil {
		idtype = "did"
	} else if _, err := syntax.ParseHandle(req.Identifier); err == nil {
		idtype = "handle"
	} else {
		idtype = "email"
	}

	var repo models.RepoActor
	var err error
	switch idtype {
	case "did":
		err = s.db.Raw(ctx, "SELECT r.*, a.* FROM repos r LEFT JOIN actors a ON r.did = a.did WHERE r.did = ?", nil, req.Identifier).Scan(&repo).Error
	case "handle":
		err = s.db.Raw(ctx, "SELECT r.*, a.* FROM actors a LEFT JOIN repos r ON a.did = r.did WHERE a.handle = ?", nil, req.Identifier).Scan(&repo).Error
	case "email":
		err = s.db.Raw(ctx, "SELECT r.*, a.* FROM repos r LEFT JOIN actors a ON r.did = a.did WHERE r.email = ?", nil, req.Identifier).Scan(&repo).Error
	}

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			helpers.InputError(w, to.StringPtr("InvalidRequest"))
			return
		}

		logger.Error("error looking up repo", "endpoint", "com.atproto.server.createSession", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(repo.Password), []byte(req.Password)); err != nil {
		if err != bcrypt.ErrMismatchedHashAndPassword {
			logger.Error("error comparing hash and password", "error", err)
		}
		helpers.InputError(w, to.StringPtr("InvalidRequest"))
		return
	}

	// if repo requires 2FA token and one hasn't been provided, return error prompting for one
	if repo.TwoFactorType != models.TwoFactorTypeNone && (req.AuthFactorToken == nil || *req.AuthFactorToken == "") {
		err = s.createAndSendTwoFactorCode(ctx, repo)
		if err != nil {
			logger.Error("sending 2FA code", "error", err)
			helpers.ServerError(w, nil)
			return
		}

		helpers.InputError(w, to.StringPtr("AuthFactorTokenRequired"))
		return
	}

	// if 2FA is required, now check that the one provided is valid
	if repo.TwoFactorType != models.TwoFactorTypeNone {
		if repo.TwoFactorCode == nil || repo.TwoFactorCodeExpiresAt == nil {
			err = s.createAndSendTwoFactorCode(ctx, repo)
			if err != nil {
				logger.Error("sending 2FA code", "error", err)
				helpers.ServerError(w, nil)
				return
			}

			helpers.InputError(w, to.StringPtr("AuthFactorTokenRequired"))
			return
		}

		if *repo.TwoFactorCode != *req.AuthFactorToken {
			helpers.InvalidTokenError(w)
			return
		}

		if time.Now().UTC().After(*repo.TwoFactorCodeExpiresAt) {
			helpers.ExpiredTokenError(w)
			return
		}
	}

	sess, err := s.createSession(ctx, &repo.Repo)
	if err != nil {
		logger.Error("error creating session", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	s.writeJSON(w, 200, ComAtprotoServerCreateSessionResponse{
		AccessJwt:       sess.AccessToken,
		RefreshJwt:      sess.RefreshToken,
		Handle:          repo.Handle,
		Did:             repo.Repo.Did,
		Email:           repo.Email,
		EmailConfirmed:  repo.EmailConfirmedAt != nil,
		EmailAuthFactor: repo.TwoFactorType != models.TwoFactorTypeNone,
		Active:          repo.Active(),
		Status:          repo.Status(),
	})
}

func (s *Server) createAndSendTwoFactorCode(ctx context.Context, repo models.RepoActor) error {
	// TODO: when implementing a new type of 2FA there should be some logic in here to send the
	// right type of code

	code := fmt.Sprintf("%s-%s", helpers.RandomVarchar(5), helpers.RandomVarchar(5))
	eat := time.Now().Add(10 * time.Minute).UTC()

	if err := s.db.Exec(ctx, "UPDATE repos SET two_factor_code = ?, two_factor_code_expires_at = ? WHERE did = ?", nil, code, eat, repo.Repo.Did).Error; err != nil {
		return fmt.Errorf("updating repo: %w", err)
	}

	if err := s.sendTwoFactorCode(repo.Email, repo.Handle, code); err != nil {
		return fmt.Errorf("sending email: %w", err)
	}

	return nil
}
