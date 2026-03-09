package server

import (
	"errors"
	"net/http"
	"time"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/oauth"
	"github.com/haileyok/cocoon/oauth/constants"
	"github.com/haileyok/cocoon/oauth/dpop"
	"github.com/haileyok/cocoon/oauth/provider"
)

type OauthParResponse struct {
	ExpiresIn  int64  `json:"expires_in"`
	RequestURI string `json:"request_uri"`
}

func (s *Server) handleOauthPar(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := s.logger.With("name", "handleOauthPar")

	if err := r.ParseForm(); err != nil {
		logger.Error("error parsing par request form", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	parRequest := provider.ParRequest{
		AuthenticateClientRequestBase: provider.AuthenticateClientRequestBase{
			ClientID: r.FormValue("client_id"),
		},
		ResponseType:        r.FormValue("response_type"),
		State:               r.FormValue("state"),
		RedirectURI:         r.FormValue("redirect_uri"),
		Scope:               r.FormValue("scope"),
		CodeChallengeMethod: r.FormValue("code_challenge_method"),
	}
	if v := r.FormValue("code_challenge"); v != "" {
		parRequest.CodeChallenge = to.StringPtr(v)
	}
	if v := r.FormValue("login_hint"); v != "" {
		parRequest.LoginHint = to.StringPtr(v)
	}
	if v := r.FormValue("dpop_jkt"); v != "" {
		parRequest.DpopJkt = to.StringPtr(v)
	}
	if v := r.FormValue("response_mode"); v != "" {
		parRequest.ResponseMode = to.StringPtr(v)
	}
	if v := r.FormValue("client_assertion_type"); v != "" {
		parRequest.ClientAssertionType = to.StringPtr(v)
	}
	if v := r.FormValue("client_assertion"); v != "" {
		parRequest.ClientAssertion = to.StringPtr(v)
	}

	if err := s.validator.Struct(parRequest); err != nil {
		logger.Error("missing parameters for par request", "error", err)
		helpers.InputError(w, nil)
		return
	}

	// TODO: this seems wrong. should be a way to get the entire request url i believe, but this will work for now
	dpopProof, err := s.oauthProvider.DpopManager.CheckProof(r.Method, "https://"+s.config.Hostname+r.URL.String(), r.Header, nil)
	if err != nil {
		if errors.Is(err, dpop.ErrUseDpopNonce) {
			nonce := s.oauthProvider.NextNonce()
			if nonce != "" {
				w.Header().Set("DPoP-Nonce", nonce)
				w.Header().Add("access-control-expose-headers", "DPoP-Nonce")
			}
			logger.Error("nonce error: use_dpop_nonce", "headers", r.Header)
			s.writeJSON(w, 400, map[string]string{
				"error": "use_dpop_nonce",
			})
			return
		}
		logger.Error("error getting dpop proof", "error", err)
		helpers.InputError(w, nil)
		return
	}

	client, clientAuth, err := s.oauthProvider.AuthenticateClient(ctx, parRequest.AuthenticateClientRequestBase, dpopProof, &provider.AuthenticateClientOptions{
		// rfc9449
		// https://github.com/bluesky-social/atproto/blob/main/packages/oauth/oauth-provider/src/oauth-provider.ts#L473
		AllowMissingDpopProof: true,
	})
	if err != nil {
		logger.Error("error authenticating client", "client_id", parRequest.ClientID, "error", err)
		helpers.InputError(w, to.StringPtr(err.Error()))
		return
	}

	if parRequest.DpopJkt == nil {
		if client.Metadata.DpopBoundAccessTokens {
			parRequest.DpopJkt = to.StringPtr(dpopProof.JKT)
		}
	} else {
		if !client.Metadata.DpopBoundAccessTokens {
			msg := "dpop bound access tokens are not enabled for this client"
			logger.Error(msg)
			helpers.InputError(w, &msg)
			return
		}

		if dpopProof.JKT != *parRequest.DpopJkt {
			msg := "supplied dpop jkt does not match header dpop jkt"
			logger.Error(msg)
			helpers.InputError(w, &msg)
			return
		}
	}

	eat := time.Now().Add(constants.ParExpiresIn)
	id := oauth.GenerateRequestId()

	authRequest := &provider.OauthAuthorizationRequest{
		RequestId:  id,
		ClientId:   client.Metadata.ClientID,
		ClientAuth: *clientAuth,
		Parameters: parRequest,
		ExpiresAt:  eat,
	}

	if err := s.db.Create(ctx, authRequest, nil).Error; err != nil {
		logger.Error("error creating auth request in db", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	uri := oauth.EncodeRequestUri(id)

	s.writeJSON(w, 201, OauthParResponse{
		ExpiresIn:  int64(constants.ParExpiresIn.Seconds()),
		RequestURI: uri,
	})
}
