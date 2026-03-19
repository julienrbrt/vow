package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/bluesky-social/indigo/api/atproto"
	"github.com/bluesky-social/indigo/events"
	"github.com/bluesky-social/indigo/util"
	"pkg.rbrt.fr/vow/internal/helpers"
	"pkg.rbrt.fr/vow/models"
)

// deleteAccountByDid removes all data belonging to did inside a single
// transaction and broadcasts an account-deleted event to relay subscribers.
// The caller is responsible for any authentication / authorisation checks
// before invoking this helper.
func (s *Server) deleteAccountByDid(ctx context.Context, did string) error {
	tx := s.db.Begin(ctx)
	if tx.Error != nil {
		return fmt.Errorf("begin transaction: %w", tx.Error)
	}

	status := "error"
	defer func() {
		if status == "error" {
			_ = tx.Rollback().Error
		}
	}()

	tables := []string{
		"DELETE FROM records WHERE did = ?",
		"DELETE FROM blobs WHERE did = ?",
		"DELETE FROM tokens WHERE did = ?",
		"DELETE FROM refresh_tokens WHERE did = ?",
		"DELETE FROM invite_codes WHERE did = ?",
		"DELETE FROM actors WHERE did = ?",
		"DELETE FROM repos WHERE did = ?",
	}

	for _, q := range tables {
		if err := tx.Exec(q, did).Error; err != nil {
			return fmt.Errorf("query %q: %w", q, err)
		}
	}

	status = "ok"

	if err := tx.Commit().Error; err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}

	if err := s.evtman.AddEvent(ctx, &events.XRPCStreamEvent{
		RepoAccount: &atproto.SyncSubscribeRepos_Account{
			Active: false,
			Did:    did,
			Status: new("deleted"),
			Seq:    time.Now().UnixMicro(),
			Time:   time.Now().Format(util.ISO8601),
		},
	}); err != nil {
		s.logger.Error("failed to add account-deleted event", "did", did, "error", err)
	}

	return nil
}

// ---------------------------------------------------------------------------
// com.atproto.server.deleteAccount — unsupported
// ---------------------------------------------------------------------------

func (s *Server) handleServerDeleteAccount(w http.ResponseWriter, r *http.Request) {
	helpers.InputError(w, new("Account deletion not supported here. Login on Vow and delete the account there."))
}

// ---------------------------------------------------------------------------
// /account/delete — browser endpoint (web session + WebAuthn assertion)
// ---------------------------------------------------------------------------

// AccountDeleteRequest carries the WebAuthn assertion response fields sent by
// the browser after the user confirms account deletion with their passkey.
type AccountDeleteRequest struct {
	CredentialID      string `json:"credentialId"`      // base64url
	ClientDataJSON    string `json:"clientDataJSON"`    // base64url
	AuthenticatorData string `json:"authenticatorData"` // base64url
	Signature         string `json:"signature"`         // base64url DER-encoded ECDSA
}

// handleAccountDelete deletes the authenticated account after verifying a
// WebAuthn assertion signed by the passkey registered for the account.
// Authentication is via the web session cookie; the passkey assertion proves
// the user still controls the device, with no password or email needed.
func (s *Server) handleAccountDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := s.logger.With("name", "handleAccountDelete")

	repo, ok := getContextValue[*models.RepoActor](r, contextKeyRepo)
	if !ok {
		s.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
		return
	}

	// The account must have a registered passkey; without it there is nothing
	// to verify against.
	if len(repo.AuthPublicKey) == 0 {
		s.writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":   "NoSigningKey",
			"message": "No passkey is registered for this account. Please register a passkey first.",
		})
		return
	}

	var req AccountDeleteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Error("error decoding request body", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	if req.ClientDataJSON == "" || req.AuthenticatorData == "" || req.Signature == "" {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "clientDataJSON, authenticatorData, and signature are required",
		})
		return
	}

	// Decode base64url fields.
	clientDataJSONBytes, err := base64.RawURLEncoding.DecodeString(req.ClientDataJSON)
	if err != nil {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid clientDataJSON encoding"})
		return
	}

	authenticatorDataBytes, err := base64.RawURLEncoding.DecodeString(req.AuthenticatorData)
	if err != nil {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid authenticatorData encoding"})
		return
	}

	signatureDER, err := base64.RawURLEncoding.DecodeString(req.Signature)
	if err != nil {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid signature encoding"})
		return
	}

	// Reconstruct the expected challenge: SHA-256("Delete account: <did>").
	// This is the same derivation used by handlePasskeyAssertionChallenge, so
	// no server-side session state is needed.
	msg := fmt.Sprintf("Delete account: %s", repo.Repo.Did)
	sum := sha256.Sum256([]byte(msg))

	// verifyAssertion checks the challenge, rpIdHash, UP flag, and P-256
	// signature. It also returns the raw (r‖s) bytes, which we discard here.
	if _, err := verifyAssertion(
		repo.AuthPublicKey,
		sum[:],
		clientDataJSONBytes,
		authenticatorDataBytes,
		signatureDER,
		s.config.Hostname,
	); err != nil {
		logger.Warn("WebAuthn assertion verification failed for account delete",
			"did", repo.Repo.Did,
			"error", err,
		)
		s.writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error": "passkey verification failed: " + err.Error(),
		})
		return
	}

	if err := s.deleteAccountByDid(ctx, repo.Repo.Did); err != nil {
		logger.Error("error deleting account", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	// Invalidate the web session so the browser is logged out immediately.
	sess, err := s.sessions.Get(r, s.config.SessionCookieKey)
	if err == nil {
		sess.Options.MaxAge = -1
		_ = sess.Save(r, w)
	}

	w.WriteHeader(http.StatusOK)
}
