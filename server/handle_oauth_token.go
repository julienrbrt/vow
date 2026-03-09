package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/golang-jwt/jwt/v4"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/oauth"
	"github.com/haileyok/cocoon/oauth/constants"
	"github.com/haileyok/cocoon/oauth/dpop"
	"github.com/haileyok/cocoon/oauth/provider"
)

type OauthTokenRequest struct {
	provider.AuthenticateClientRequestBase
	GrantType    string  `form:"grant_type" json:"grant_type"`
	Code         *string `form:"code" json:"code,omitempty"`
	CodeVerifier *string `form:"code_verifier" json:"code_verifier,omitempty"`
	RedirectURI  *string `form:"redirect_uri" json:"redirect_uri,omitempty"`
	RefreshToken *string `form:"refresh_token" json:"refresh_token,omitempty"`
}

type OauthTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	ExpiresIn    int64  `json:"expires_in"`
	Sub          string `json:"sub"`
}

func (s *Server) handleOauthToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := s.logger.With("name", "handleOauthToken")

	if err := r.ParseForm(); err != nil {
		logger.Error("error parsing token request form", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	req := OauthTokenRequest{
		GrantType: r.FormValue("grant_type"),
	}
	if v := r.FormValue("code"); v != "" {
		req.Code = to.StringPtr(v)
	}
	if v := r.FormValue("code_verifier"); v != "" {
		req.CodeVerifier = to.StringPtr(v)
	}
	if v := r.FormValue("redirect_uri"); v != "" {
		req.RedirectURI = to.StringPtr(v)
	}
	if v := r.FormValue("refresh_token"); v != "" {
		req.RefreshToken = to.StringPtr(v)
	}
	if v := r.FormValue("client_assertion_type"); v != "" {
		req.ClientAssertionType = to.StringPtr(v)
	}
	if v := r.FormValue("client_assertion"); v != "" {
		req.ClientAssertion = to.StringPtr(v)
	}
	req.AuthenticateClientRequestBase = provider.AuthenticateClientRequestBase{
		ClientID:            r.FormValue("client_id"),
		ClientAssertionType: req.ClientAssertionType,
		ClientAssertion:     req.ClientAssertion,
	}

	proof, err := s.oauthProvider.DpopManager.CheckProof(r.Method, r.URL.String(), r.Header, nil)
	if err != nil {
		if errors.Is(err, dpop.ErrUseDpopNonce) {
			nonce := s.oauthProvider.NextNonce()
			if nonce != "" {
				w.Header().Set("DPoP-Nonce", nonce)
				w.Header().Add("access-control-expose-headers", "DPoP-Nonce")
			}
			s.writeJSON(w, 400, map[string]string{
				"error": "use_dpop_nonce",
			})
			return
		}
		logger.Error("error getting dpop proof", "error", err)
		helpers.InputError(w, nil)
		return
	}

	client, clientAuth, err := s.oauthProvider.AuthenticateClient(ctx, req.AuthenticateClientRequestBase, proof, &provider.AuthenticateClientOptions{
		AllowMissingDpopProof: true,
	})
	if err != nil {
		logger.Error("error authenticating client", "client_id", req.ClientID, "error", err)
		helpers.InputError(w, to.StringPtr(err.Error()))
		return
	}

	// TODO: this should come from an oauth provider config
	if !slices.Contains([]string{"authorization_code", "refresh_token"}, req.GrantType) {
		helpers.InputError(w, to.StringPtr(fmt.Sprintf(`"%s" grant type is not supported by the server`, req.GrantType)))
		return
	}

	if !slices.Contains(client.Metadata.GrantTypes, req.GrantType) {
		helpers.InputError(w, to.StringPtr(fmt.Sprintf(`"%s" grant type is not supported by the client`, req.GrantType)))
		return
	}

	if req.GrantType == "authorization_code" {
		if req.Code == nil {
			helpers.InputError(w, to.StringPtr(`"code" is required"`))
			return
		}

		var authReq provider.OauthAuthorizationRequest
		// get the lil guy and delete him
		if err := s.db.Raw(ctx, "DELETE FROM oauth_authorization_requests WHERE code = ? RETURNING *", nil, *req.Code).Scan(&authReq).Error; err != nil {
			logger.Error("error finding authorization request", "error", err)
			helpers.ServerError(w, nil)
			return
		}

		if req.RedirectURI == nil || *req.RedirectURI != authReq.Parameters.RedirectURI {
			helpers.InputError(w, to.StringPtr(`"redirect_uri" mismatch`))
			return
		}

		if authReq.Parameters.CodeChallenge != nil {
			if req.CodeVerifier == nil {
				helpers.InputError(w, to.StringPtr(`"code_verifier" is required`))
				return
			}

			if len(*req.CodeVerifier) < 43 {
				helpers.InputError(w, to.StringPtr(`"code_verifier" is too short`))
				return
			}

			switch authReq.Parameters.CodeChallengeMethod {
			case "", "plain":
				if authReq.Parameters.CodeChallenge != req.CodeVerifier {
					helpers.InputError(w, to.StringPtr("invalid code_verifier"))
					return
				}
			case "S256":
				inputChal, err := base64.RawURLEncoding.DecodeString(*authReq.Parameters.CodeChallenge)
				if err != nil {
					logger.Error("error decoding code challenge", "error", err)
					helpers.ServerError(w, nil)
					return
				}

				h := sha256.New()
				h.Write([]byte(*req.CodeVerifier))
				compdChal := h.Sum(nil)

				if !bytes.Equal(inputChal, compdChal) {
					helpers.InputError(w, to.StringPtr("invalid code_verifier"))
					return
				}
			default:
				helpers.InputError(w, to.StringPtr("unsupported code_challenge_method "+authReq.Parameters.CodeChallengeMethod))
				return
			}
		} else if req.CodeVerifier != nil {
			helpers.InputError(w, to.StringPtr("code_challenge parameter wasn't provided"))
			return
		}

		repo, err := s.getRepoActorByDid(ctx, *authReq.Sub)
		if err != nil {
			helpers.InputError(w, to.StringPtr("unable to find actor"))
			return
		}

		now := time.Now()
		eat := now.Add(constants.TokenMaxAge)
		id := oauth.GenerateTokenId()

		refreshToken := oauth.GenerateRefreshToken()

		accessClaims := jwt.MapClaims{
			"scope":     authReq.Parameters.Scope,
			"aud":       s.config.Did,
			"sub":       repo.Repo.Did,
			"iat":       now.Unix(),
			"exp":       eat.Unix(),
			"jti":       id,
			"client_id": authReq.ClientId,
		}

		if authReq.Parameters.DpopJkt != nil {
			accessClaims["cnf"] = *authReq.Parameters.DpopJkt
		}

		accessToken := jwt.NewWithClaims(jwt.SigningMethodES256, accessClaims)
		accessString, err := accessToken.SignedString(s.privateKey)
		if err != nil {
			helpers.ServerError(w, nil)
			return
		}

		if err := s.db.Create(ctx, &provider.OauthToken{
			ClientId:     authReq.ClientId,
			ClientAuth:   *clientAuth,
			Parameters:   authReq.Parameters,
			ExpiresAt:    eat,
			DeviceId:     "",
			Sub:          repo.Repo.Did,
			Code:         *authReq.Code,
			Token:        accessString,
			RefreshToken: refreshToken,
			Ip:           authReq.Ip,
		}, nil).Error; err != nil {
			logger.Error("error creating token in db", "error", err)
			helpers.ServerError(w, nil)
			return
		}

		// prob not needed
		tokenType := "Bearer"
		if authReq.Parameters.DpopJkt != nil {
			tokenType = "DPoP"
		}

		s.writeJSON(w, 200, OauthTokenResponse{
			AccessToken:  accessString,
			RefreshToken: refreshToken,
			TokenType:    tokenType,
			Scope:        authReq.Parameters.Scope,
			ExpiresIn:    int64(eat.Sub(time.Now()).Seconds()),
			Sub:          repo.Repo.Did,
		})
		return
	}

	if req.GrantType == "refresh_token" {
		if req.RefreshToken == nil {
			helpers.InputError(w, to.StringPtr(`"refresh_token" is required`))
			return
		}

		var oauthToken provider.OauthToken
		if err := s.db.Raw(ctx, "SELECT * FROM oauth_tokens WHERE refresh_token = ?", nil, req.RefreshToken).Scan(&oauthToken).Error; err != nil {
			logger.Error("error finding oauth token by refresh token", "error", err, "refresh_token", req.RefreshToken)
			helpers.ServerError(w, nil)
			return
		}

		if client.Metadata.ClientID != oauthToken.ClientId {
			helpers.InputError(w, to.StringPtr(`"client_id" mismatch`))
			return
		}

		if clientAuth.Method != oauthToken.ClientAuth.Method {
			helpers.InputError(w, to.StringPtr(`"client authentication method mismatch`))
			return
		}

		if *oauthToken.Parameters.DpopJkt != proof.JKT {
			helpers.InputError(w, to.StringPtr("dpop proof does not match expected jkt"))
			return
		}

		ageRes := oauth.GetSessionAgeFromToken(oauthToken)

		if ageRes.SessionExpired {
			helpers.InputError(w, to.StringPtr("Session expired"))
			return
		}

		if ageRes.RefreshExpired {
			helpers.InputError(w, to.StringPtr("Refresh token expired"))
			return
		}

		if client.Metadata.DpopBoundAccessTokens && oauthToken.Parameters.DpopJkt == nil {
			// why? ref impl
			helpers.InputError(w, to.StringPtr("dpop jkt is required for dpop bound access tokens"))
			return
		}

		nextTokenId := oauth.GenerateTokenId()
		nextRefreshToken := oauth.GenerateRefreshToken()

		now := time.Now()
		eat := now.Add(constants.TokenMaxAge)

		accessClaims := jwt.MapClaims{
			"scope":     oauthToken.Parameters.Scope,
			"aud":       s.config.Did,
			"sub":       oauthToken.Sub,
			"iat":       now.Unix(),
			"exp":       eat.Unix(),
			"jti":       nextTokenId,
			"client_id": oauthToken.ClientId,
		}

		if oauthToken.Parameters.DpopJkt != nil {
			accessClaims["cnf"] = oauthToken.Parameters.DpopJkt
		}

		accessToken := jwt.NewWithClaims(jwt.SigningMethodES256, accessClaims)
		accessString, err := accessToken.SignedString(s.privateKey)
		if err != nil {
			helpers.ServerError(w, nil)
			return
		}

		if err := s.db.Exec(ctx, "UPDATE oauth_tokens SET token = ?, refresh_token = ?, expires_at = ?, updated_at = ? WHERE refresh_token = ?", nil, accessString, nextRefreshToken, eat, now, *req.RefreshToken).Error; err != nil {
			logger.Error("error updating token", "error", err)
			helpers.ServerError(w, nil)
			return
		}

		// prob not needed
		tokenType := "Bearer"
		if oauthToken.Parameters.DpopJkt != nil {
			tokenType = "DPoP"
		}

		s.writeJSON(w, 200, OauthTokenResponse{
			AccessToken:  accessString,
			RefreshToken: nextRefreshToken,
			TokenType:    tokenType,
			Scope:        oauthToken.Parameters.Scope,
			ExpiresIn:    int64(eat.Sub(time.Now()).Seconds()),
			Sub:          oauthToken.Sub,
		})
		return
	}

	helpers.InputError(w, to.StringPtr(fmt.Sprintf(`grant type "%s" is not supported`, req.GrantType)))
}
