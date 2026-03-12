package server

import (
	"encoding/base64"
	"net/http"
	"time"

	"github.com/hako/durafmt"
	"pkg.rbrt.fr/vow/oauth"
	"pkg.rbrt.fr/vow/oauth/constants"
	"pkg.rbrt.fr/vow/oauth/provider"
)

func (s *Server) handleAccount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := s.logger.With("name", "handleAuth")

	repo, sess, err := s.getSessionRepoOrErr(r)
	if err != nil {
		http.Redirect(w, r, "/account/signin", http.StatusSeeOther)
		return
	}

	oldestPossibleSession := time.Now().Add(constants.ConfidentialClientSessionLifetime)

	var tokens []provider.OauthToken
	if err := s.db.Raw(ctx, "SELECT * FROM oauth_tokens WHERE sub = ? AND created_at < ? ORDER BY created_at ASC", nil, repo.Repo.Did, oldestPossibleSession).Scan(&tokens).Error; err != nil {
		logger.Error("couldnt fetch oauth sessions for account", "did", repo.Repo.Did, "error", err)
		sess.AddFlash("Unable to fetch sessions. See server logs for more details.", "error")
		if err := sess.Save(r, w); err != nil {
			logger.Error("failed to save session", "error", err)
		}
		if err := s.renderTemplate(w, "account.html", map[string]any{
			"flashes": s.getFlashesFromSession(w, r, sess),
		}); err != nil {
			logger.Error("failed to render template", "error", err)
		}
		return
	}

	now := time.Now()

	tokenInfo := []map[string]string{}
	for _, t := range tokens {
		ageRes := oauth.GetSessionAgeFromToken(t)
		maxTime := constants.PublicClientSessionLifetime
		if t.ClientAuth.Method != "none" {
			maxTime = constants.ConfidentialClientSessionLifetime
		}

		var clientName string
		metadata, err := s.oauthProvider.ClientManager.GetClient(ctx, t.ClientId)
		if err != nil {
			clientName = t.ClientId
		} else {
			clientName = metadata.Metadata.ClientName
		}

		tokenInfo = append(tokenInfo, map[string]string{
			"ClientName":  clientName,
			"Age":         durafmt.Parse(ageRes.SessionAge).LimitFirstN(2).String(),
			"LastUpdated": durafmt.Parse(now.Sub(t.UpdatedAt)).LimitFirstN(2).String(),
			"ExpiresIn":   durafmt.Parse(now.Add(maxTime).Sub(now)).LimitFirstN(2).String(),
			"Token":       t.Token,
			"Ip":          t.Ip,
		})
	}

	// Encode the credential ID as base64url so the template can pass it to
	// navigator.credentials.get() as the allowCredentials entry.
	credentialID := ""
	if len(repo.CredentialID) > 0 {
		credentialID = base64.RawURLEncoding.EncodeToString(repo.CredentialID)
	}

	if err := s.renderTemplate(w, "account.html", map[string]any{
		"Handle":        repo.Handle,
		"Did":           repo.Repo.Did,
		"HasSigningKey": len(repo.SigningPublicKey) > 0,
		"CredentialID":  credentialID,
		"Tokens":        tokenInfo,
		"flashes":       s.getFlashesFromSession(w, r, sess),
	}); err != nil {
		logger.Error("failed to render template", "error", err)
	}
}
