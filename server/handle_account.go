package server

import (
	"net/http"
	"time"

	"github.com/haileyok/cocoon/oauth"
	"github.com/haileyok/cocoon/oauth/constants"
	"github.com/haileyok/cocoon/oauth/provider"
	"github.com/hako/durafmt"
)

func (s *Server) handleAccount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := s.logger.With("name", "handleAuth")

	repo, sess, err := s.getSessionRepoOrErr(r)
	if err != nil {
		http.Redirect(w, r, "/account/signin", 303)
		return
	}

	oldestPossibleSession := time.Now().Add(constants.ConfidentialClientSessionLifetime)

	var tokens []provider.OauthToken
	if err := s.db.Raw(ctx, "SELECT * FROM oauth_tokens WHERE sub = ? AND created_at < ? ORDER BY created_at ASC", nil, repo.Repo.Did, oldestPossibleSession).Scan(&tokens).Error; err != nil {
		logger.Error("couldnt fetch oauth sessions for account", "did", repo.Repo.Did, "error", err)
		sess.AddFlash("Unable to fetch sessions. See server logs for more details.", "error")
		sess.Save(r, w)
		s.renderTemplate(w, "account.html", map[string]any{
			"flashes": getFlashesFromSession(w, r, sess),
		})
		return
	}

	var filtered []provider.OauthToken
	for _, t := range tokens {
		ageRes := oauth.GetSessionAgeFromToken(t)
		if ageRes.SessionExpired {
			continue
		}
		filtered = append(filtered, t)
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

	s.renderTemplate(w, "account.html", map[string]any{
		"Repo":    repo,
		"Tokens":  tokenInfo,
		"flashes": getFlashesFromSession(w, r, sess),
	})
}
