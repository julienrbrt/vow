package server

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/bluesky-social/indigo/api/atproto"
	"github.com/bluesky-social/indigo/events"
	"github.com/bluesky-social/indigo/util"
	gethcrypto "github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/bcrypt"
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
		"DELETE FROM reserved_keys WHERE did = ?",
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
// com.atproto.server.deleteAccount — legacy XRPC endpoint (did + password + token)
// ---------------------------------------------------------------------------

type ComAtprotoServerDeleteAccountRequest struct {
	Did      string `json:"did"      validate:"required"`
	Password string `json:"password" validate:"required"`
	Token    string `json:"token"    validate:"required"`
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
		s.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "account not found"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(urepo.Password), []byte(req.Password)); err != nil {
		logger.Error("password mismatch", "error", err)
		s.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Invalid did or password"})
		return
	}

	if urepo.AccountDeleteCode == nil || urepo.AccountDeleteCodeExpiresAt == nil {
		logger.Error("no deletion token found for account")
		s.writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":   "InvalidToken",
			"message": "Token is invalid",
		})
		return
	}

	if *urepo.AccountDeleteCode != req.Token {
		logger.Error("deletion token mismatch")
		s.writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":   "InvalidToken",
			"message": "Token is invalid",
		})
		return
	}

	if time.Now().UTC().After(*urepo.AccountDeleteCodeExpiresAt) {
		logger.Error("deletion token expired")
		s.writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":   "ExpiredToken",
			"message": "Token is expired",
		})
		return
	}

	if err := s.deleteAccountByDid(ctx, req.Did); err != nil {
		logger.Error("error deleting account", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// ---------------------------------------------------------------------------
// /account/delete — browser endpoint (web session + wallet signature)
// ---------------------------------------------------------------------------

type AccountDeleteRequest struct {
	WalletAddress string `json:"walletAddress" validate:"required"`
	Signature     string `json:"signature"     validate:"required"`
}

// handleAccountDelete deletes the authenticated account after verifying that
// the request is signed by the wallet whose public key is registered with the
// account. Authentication is done via the web session cookie; the wallet
// signature proves the user still controls the key, with no email or password
// needed.
func (s *Server) handleAccountDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := s.logger.With("name", "handleAccountDelete")

	repo, ok := getContextValue[*models.RepoActor](r, contextKeyRepo)
	if !ok {
		s.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
		return
	}

	// The account must have a registered signing key; without it we have no
	// wallet to verify against.
	if len(repo.PublicKey) == 0 {
		s.writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":   "NoSigningKey",
			"message": "No signing key is registered for this account. Please register your wallet first.",
		})
		return
	}

	var req AccountDeleteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Error("error decoding request body", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	if err := s.validator.Struct(&req); err != nil {
		logger.Error("validation failed", "error", err)
		s.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "walletAddress and signature are required"})
		return
	}

	// Decode the 65-byte personal_sign signature.
	sigHex := strings.TrimPrefix(req.Signature, "0x")
	sig, err := hex.DecodeString(sigHex)
	if err != nil || len(sig) != 65 {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "signature must be a 65-byte hex string"})
		return
	}

	// personal_sign uses v=27/28; go-ethereum SigToPub expects v=0/1.
	if sig[64] >= 27 {
		sig[64] -= 27
	}

	// Hash the message with the Ethereum personal_sign envelope.
	msg := fmt.Sprintf("Delete account: %s", repo.Repo.Did)
	msgHash := gethcrypto.Keccak256(
		fmt.Appendf(nil, "\x19Ethereum Signed Message:\n%d%s", len(msg), msg),
	)

	// Recover the public key from the signature.
	ecPub, err := gethcrypto.SigToPub(msgHash, sig)
	if err != nil {
		logger.Warn("public key recovery failed", "error", err)
		s.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "could not recover public key from signature"})
		return
	}

	// Verify the recovered address matches the claimed wallet address.
	recoveredAddr := gethcrypto.PubkeyToAddress(*ecPub).Hex()
	if !strings.EqualFold(recoveredAddr, req.WalletAddress) {
		logger.Warn("address mismatch", "claimed", req.WalletAddress, "recovered", recoveredAddr)
		s.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "signature does not match the provided wallet address"})
		return
	}

	// Verify the recovered address matches the wallet registered on the account.
	registeredAddr := repo.EthereumAddress()
	if !strings.EqualFold(recoveredAddr, registeredAddr) {
		logger.Warn("wallet not registered for account",
			"recovered", recoveredAddr,
			"registered", registeredAddr,
			"did", repo.Repo.Did,
		)
		s.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "signature wallet does not match the key registered for this account"})
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
