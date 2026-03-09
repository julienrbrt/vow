package server

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/bluesky-social/indigo/api/atproto"
	"github.com/bluesky-social/indigo/events"
	"github.com/bluesky-social/indigo/util"
	"golang.org/x/crypto/bcrypt"
	"pkg.rbrt.fr/vow/internal/helpers"
)

type ComAtprotoServerDeleteAccountRequest struct {
	Did      string `json:"did" validate:"required"`
	Password string `json:"password" validate:"required"`
	Token    string `json:"token" validate:"required"`
}

func (s *Server) handleServerDeleteAccount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := s.logger.With("name", "handleServerDeleteAccount")

	var req ComAtprotoServerDeleteAccountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Error("error decoding", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	if err := s.validator.Struct(&req); err != nil {
		logger.Error("error validating", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	urepo, err := s.getRepoActorByDid(ctx, req.Did)
	if err != nil {
		logger.Error("error getting repo", "error", err)
		s.writeJSON(w, 400, map[string]string{"error": "account not found"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(urepo.Password), []byte(req.Password)); err != nil {
		logger.Error("password mismatch", "error", err)
		s.writeJSON(w, 401, map[string]string{"error": "Invalid did or password"})
		return
	}

	if urepo.AccountDeleteCode == nil || urepo.AccountDeleteCodeExpiresAt == nil {
		logger.Error("no deletion token found for account")
		s.writeJSON(w, 400, map[string]any{
			"error":   "InvalidToken",
			"message": "Token is invalid",
		})
		return
	}

	if *urepo.AccountDeleteCode != req.Token {
		logger.Error("deletion token mismatch")
		s.writeJSON(w, 400, map[string]any{
			"error":   "InvalidToken",
			"message": "Token is invalid",
		})
		return
	}

	if time.Now().UTC().After(*urepo.AccountDeleteCodeExpiresAt) {
		logger.Error("deletion token expired")
		s.writeJSON(w, 400, map[string]any{
			"error":   "ExpiredToken",
			"message": "Token is expired",
		})
		return
	}

	tx := s.db.Begin(ctx)
	if tx.Error != nil {
		logger.Error("error starting transaction", "error", tx.Error)
		helpers.ServerError(w, nil)
		return
	}

	status := "error"
	defer func() {
		if status == "error" {
			if err := tx.Rollback().Error; err != nil {
				logger.Error("error rolling back after delete failure", "err", err)
			}
		}
	}()

	if err := tx.Exec("DELETE FROM blocks WHERE did = ?", req.Did).Error; err != nil {
		logger.Error("error deleting blocks", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	if err := tx.Exec("DELETE FROM records WHERE did = ?", req.Did).Error; err != nil {
		logger.Error("error deleting records", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	if err := tx.Exec("DELETE FROM blobs WHERE did = ?", req.Did).Error; err != nil {
		logger.Error("error deleting blobs", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	if err := tx.Exec("DELETE FROM tokens WHERE did = ?", req.Did).Error; err != nil {
		logger.Error("error deleting tokens", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	if err := tx.Exec("DELETE FROM refresh_tokens WHERE did = ?", req.Did).Error; err != nil {
		logger.Error("error deleting refresh tokens", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	if err := tx.Exec("DELETE FROM reserved_keys WHERE did = ?", req.Did).Error; err != nil {
		logger.Error("error deleting reserved keys", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	if err := tx.Exec("DELETE FROM invite_codes WHERE did = ?", req.Did).Error; err != nil {
		logger.Error("error deleting invite codes", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	if err := tx.Exec("DELETE FROM actors WHERE did = ?", req.Did).Error; err != nil {
		logger.Error("error deleting actor", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	if err := tx.Exec("DELETE FROM repos WHERE did = ?", req.Did).Error; err != nil {
		logger.Error("error deleting repo", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	status = "ok"

	if err := tx.Commit().Error; err != nil {
		logger.Error("error committing transaction", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	if err := s.evtman.AddEvent(context.TODO(), &events.XRPCStreamEvent{
		RepoAccount: &atproto.SyncSubscribeRepos_Account{
			Active: false,
			Did:    req.Did,
			Status: to.StringPtr("deleted"),
			Seq:    time.Now().UnixMicro(),
			Time:   time.Now().Format(util.ISO8601),
		},
	}); err != nil {
		s.logger.Error("failed to add event", "error", err)
	}

	w.WriteHeader(http.StatusOK)
}
