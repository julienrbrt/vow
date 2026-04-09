package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/bluesky-social/indigo/atproto/syntax"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"pkg.rbrt.fr/vow/internal/helpers"
	"pkg.rbrt.fr/vow/models"
)

type ComAtprotoServerCreateSessionRequest struct {
	Identifier string `json:"identifier" validate:"required"`
	Password   string `json:"password" validate:"required"`
}

type ComAtprotoServerCreateSessionResponse struct {
	AccessJwt      string  `json:"accessJwt"`
	RefreshJwt     string  `json:"refreshJwt"`
	Handle         string  `json:"handle"`
	Did            string  `json:"did"`
	Email          string  `json:"email"`
	EmailConfirmed bool    `json:"emailConfirmed"`
	Active         bool    `json:"active"`
	Status         *string `json:"status,omitempty"`
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
				helpers.InputError(w, new("InvalidRequest"))
				return
			}

			if verr.Field == "Password" {
				helpers.InputError(w, new("InvalidRequest"))
				return
			}
		}

		helpers.InputError(w, nil)
		return
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
			helpers.InputError(w, new("InvalidRequest"))
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
		helpers.InputError(w, new("InvalidRequest"))
		return
	}

	sess, err := s.createSession(ctx, &repo.Repo)
	if err != nil {
		logger.Error("error creating session", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	s.writeJSON(w, 200, ComAtprotoServerCreateSessionResponse{
		AccessJwt:      sess.AccessToken,
		RefreshJwt:     sess.RefreshToken,
		Handle:         repo.Handle,
		Did:            repo.Repo.Did,
		Email:          repo.Email,
		EmailConfirmed: repo.EmailConfirmedAt != nil,
		Active:         repo.Active(),
		Status:         repo.Status(),
	})
}
