package server

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"pkg.rbrt.fr/vow/internal/helpers"
	"pkg.rbrt.fr/vow/oauth"
	"pkg.rbrt.fr/vow/oauth/constants"
	"pkg.rbrt.fr/vow/oauth/provider"
)

type HandleOauthAuthorizeGetInput struct {
	RequestUri string `query:"request_uri"`
}

func (s *Server) handleOauthAuthorizeGet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	logger := s.logger.With("name", "handleOauthAuthorizeGet")

	requestUri := r.URL.Query().Get("request_uri")

	var reqId string
	if requestUri != "" {
		id, err := oauth.DecodeRequestUri(requestUri)
		if err != nil {
			logger.Error("no request uri found in input", "url", r.URL.String())
			helpers.InputError(w, new("no request uri"))
			return
		}
		reqId = id
	} else {
		parRequest := provider.ParRequest{
			AuthenticateClientRequestBase: provider.AuthenticateClientRequestBase{
				ClientID: r.URL.Query().Get("client_id"),
			},
			ResponseType:        r.URL.Query().Get("response_type"),
			State:               r.URL.Query().Get("state"),
			RedirectURI:         r.URL.Query().Get("redirect_uri"),
			Scope:               r.URL.Query().Get("scope"),
			CodeChallengeMethod: r.URL.Query().Get("code_challenge_method"),
		}
		if v := r.URL.Query().Get("code_challenge"); v != "" {
			parRequest.CodeChallenge = new(v)
		}
		if v := r.URL.Query().Get("login_hint"); v != "" {
			parRequest.LoginHint = new(v)
		}
		if v := r.URL.Query().Get("dpop_jkt"); v != "" {
			parRequest.DpopJkt = new(v)
		}
		if v := r.URL.Query().Get("response_mode"); v != "" {
			parRequest.ResponseMode = new(v)
		}

		if err := s.validator.Struct(parRequest); err != nil {
			// render page for logged out dev
			if s.config.Version == "dev" && parRequest.ClientID == "" {
				if err := s.renderTemplate(w, "authorize.html", map[string]any{
					"Scopes":     []string{"atproto", "transition:generic"},
					"AppName":    "DEV MODE AUTHORIZATION PAGE",
					"Handle":     "paula.rbrt.fr",
					"RequestUri": "",
				}); err != nil {
					logger.Error("failed to render template", "error", err)
				}
				return
			}
			helpers.InputError(w, new("no request uri and invalid parameters"))
			return
		}

		client, clientAuth, err := s.oauthProvider.AuthenticateClient(ctx, parRequest.AuthenticateClientRequestBase, nil, &provider.AuthenticateClientOptions{
			AllowMissingDpopProof: true,
		})
		if err != nil {
			s.logger.Error("error authenticating client in standard request", "client_id", parRequest.ClientID, "error", err)
			helpers.ServerError(w, new(err.Error()))
			return
		}

		if parRequest.DpopJkt != nil {
			if !client.Metadata.DpopBoundAccessTokens {
				msg := "dpop bound access tokens are not enabled for this client"
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
			s.logger.Error("error creating auth request in db", "error", err)
			helpers.ServerError(w, nil)
			return
		}

		requestUri = oauth.EncodeRequestUri(id)
		reqId = id
	}

	repo, _, err := s.getSessionRepoOrErr(r)
	if err != nil {
		http.Redirect(w, r, "/account/signin?"+r.URL.Query().Encode(), http.StatusSeeOther)
		return
	}

	var req provider.OauthAuthorizationRequest
	if err := s.db.Raw(ctx, "SELECT * FROM oauth_authorization_requests WHERE request_id = ?", nil, reqId).Scan(&req).Error; err != nil {
		helpers.ServerError(w, new(err.Error()))
		return
	}

	clientId := r.URL.Query().Get("client_id")
	if clientId != req.ClientId {
		helpers.InputError(w, new("client id does not match the client id for the supplied request"))
		return
	}

	client, err := s.oauthProvider.ClientManager.GetClient(r.Context(), req.ClientId)
	if err != nil {
		helpers.ServerError(w, new(err.Error()))
		return
	}

	scopes := strings.Split(req.Parameters.Scope, " ")
	appName := client.Metadata.ClientName

	data := map[string]any{
		"Scopes":      scopes,
		"AppName":     appName,
		"RequestUri":  requestUri,
		"QueryParams": r.URL.Query().Encode(),
		"Handle":      repo.Handle,
	}

	if err := s.renderTemplate(w, "authorize.html", data); err != nil {
		logger.Error("failed to render template", "error", err)
	}
}

type OauthAuthorizePostRequest struct {
	RequestUri    string `form:"request_uri"`
	AcceptOrRejct string `form:"accept_or_reject"`
}

func (s *Server) handleOauthAuthorizePost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := s.logger.With("name", "handleOauthAuthorizePost")

	repo, _, err := s.getSessionRepoOrErr(r)
	if err != nil {
		http.Redirect(w, r, "/account/signin", http.StatusSeeOther)
		return
	}

	if err := r.ParseForm(); err != nil {
		logger.Error("error parsing authorize post form", "error", err)
		helpers.InputError(w, nil)
		return
	}

	req := OauthAuthorizePostRequest{
		RequestUri:    r.FormValue("request_uri"),
		AcceptOrRejct: r.FormValue("accept_or_reject"),
	}

	reqId, err := oauth.DecodeRequestUri(req.RequestUri)
	if err != nil {
		helpers.InputError(w, new(err.Error()))
		return
	}

	var authReq provider.OauthAuthorizationRequest
	if err := s.db.Raw(ctx, "SELECT * FROM oauth_authorization_requests WHERE request_id = ?", nil, reqId).Scan(&authReq).Error; err != nil {
		helpers.ServerError(w, new(err.Error()))
		return
	}

	client, err := s.oauthProvider.ClientManager.GetClient(r.Context(), authReq.ClientId)
	if err != nil {
		helpers.ServerError(w, new(err.Error()))
		return
	}

	// TODO: figure out how im supposed to actually redirect
	if req.AcceptOrRejct == "reject" {
		http.Redirect(w, r, client.Metadata.ClientURI, http.StatusSeeOther)
		return
	}

	if time.Now().After(authReq.ExpiresAt) {
		helpers.InputError(w, new("the request has expired"))
		return
	}

	if authReq.Sub != nil || authReq.Code != nil {
		helpers.InputError(w, new("this request was already authorized"))
		return
	}

	code := oauth.GenerateCode()

	// Use the first non-loopback remote address as the IP
	ip := r.RemoteAddr
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		ip = strings.Split(forwarded, ",")[0]
	}

	if err := s.db.Exec(ctx, "UPDATE oauth_authorization_requests SET sub = ?, code = ?, accepted = ?, ip = ? WHERE request_id = ?", nil, repo.Repo.Did, code, true, ip, reqId).Error; err != nil {
		logger.Error("error updating authorization request", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	q := url.Values{}
	q.Set("state", authReq.Parameters.State)
	q.Set("iss", "https://"+s.config.Hostname)
	q.Set("code", code)

	hashOrQuestion := "?"
	if authReq.Parameters.ResponseMode != nil {
		switch *authReq.Parameters.ResponseMode {
		case "fragment":
			hashOrQuestion = "#"
		case "query":
			// do nothing
		default:
			if authReq.Parameters.ResponseType != "code" {
				hashOrQuestion = "#"
			}
		}
	} else {
		if authReq.Parameters.ResponseType != "code" {
			hashOrQuestion = "#"
		}
	}

	_ = fmt.Sprintf // avoid unused import if fmt ends up unused
	http.Redirect(w, r, authReq.Parameters.RedirectURI+hashOrQuestion+q.Encode(), http.StatusSeeOther)
}
