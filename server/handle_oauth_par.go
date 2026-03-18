package server

import (
	"errors"
	"net/http"
	"time"

	"pkg.rbrt.fr/vow/internal/helpers"
	"pkg.rbrt.fr/vow/oauth"
	"pkg.rbrt.fr/vow/oauth/constants"
	"pkg.rbrt.fr/vow/oauth/dpop"
	"pkg.rbrt.fr/vow/oauth/provider"
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
		parRequest.CodeChallenge = new(v)
	}
	if v := r.FormValue("login_hint"); v != "" {
		parRequest.LoginHint = new(v)
	}
	if v := r.FormValue("dpop_jkt"); v != "" {
		parRequest.DpopJkt = new(v)
	}
	if v := r.FormValue("response_mode"); v != "" {
		parRequest.ResponseMode = new(v)
	}
	if v := r.FormValue("client_assertion_type"); v != "" {
		parRequest.ClientAssertionType = new(v)
	}
	if v := r.FormValue("client_assertion"); v != "" {
		parRequest.ClientAssertion = new(v)
	}

	if err := s.validator.Struct(parRequest); err != nil {
		logger.Error("missing parameters for par request", "error", err)
		helpers.InputError(w, nil)
		return
	}

	scheme := "https"
	if r.TLS == nil && r.Header.Get("X-Forwarded-Proto") == "" {
		scheme = "http"
	} else if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		scheme = proto
	}
	host := r.Host
	if fwdHost := r.Header.Get("X-Forwarded-Host"); fwdHost != "" {
		host = fwdHost
	}
	dpopProof, err := s.oauthProvider.DpopManager.CheckProof(r.Method, scheme+"://"+host+r.URL.String(), r.Header, nil)
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
		helpers.InputError(w, new(err.Error()))
		return
	}

	if parRequest.DpopJkt == nil {
		if client.Metadata.DpopBoundAccessTokens {
			if dpopProof.JKT == "" {
				msg := "dpop proof is required for dpop bound access tokens"
				logger.Error(msg)
				helpers.InputError(w, &msg)
				return
			}
			parRequest.DpopJkt = new(dpopProof.JKT)
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
