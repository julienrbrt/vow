package server

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	atproto_identity "github.com/bluesky-social/indigo/atproto/identity"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/golang-jwt/jwt/v4"
	"gorm.io/gorm"
	"pkg.rbrt.fr/vow/internal/helpers"
	"pkg.rbrt.fr/vow/models"
	"pkg.rbrt.fr/vow/oauth/dpop"
	"pkg.rbrt.fr/vow/oauth/provider"
)

// context keys for values set by middleware
type contextKey string

const (
	contextKeyRepo   contextKey = "repo"
	contextKeyDid    contextKey = "did"
	contextKeyToken  contextKey = "token"
	contextKeyScopes contextKey = "scopes"

	// used by proxy handler to override token fields
	contextKeyProxyTokenLxm contextKey = "proxyTokenLxm"
	contextKeyProxyTokenAud contextKey = "proxyTokenAud"
)

func setContextValue(r *http.Request, key contextKey, value any) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), key, value))
}

func getContextValue[T any](r *http.Request, key contextKey) (T, bool) {
	v, ok := r.Context().Value(key).(T)
	return v, ok
}

func (s *Server) handleAdminMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok || username != "admin" || subtle.ConstantTimeCompare([]byte(password), []byte(s.config.AdminPassword)) != 1 {
			helpers.InputError(w, new("Unauthorized"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// handleWebSessionMiddleware authenticates requests using the web session
// cookie (set by handleAccountSigninPost). It is intended for browser-facing
// routes on the account page where a Bearer token is not available.
func (s *Server) handleWebSessionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		sess, err := s.sessions.Get(r, s.config.SessionCookieKey)
		if err != nil {
			s.writeJSON(w, 401, map[string]string{"error": "Unauthorized"})
			return
		}

		did, ok := sess.Values["did"].(string)
		if !ok || did == "" {
			s.writeJSON(w, 401, map[string]string{"error": "Unauthorized"})
			return
		}

		repo, err := s.getRepoActorByDid(ctx, did)
		if err != nil {
			s.writeJSON(w, 401, map[string]string{"error": "Unauthorized"})
			return
		}

		r = setContextValue(r, contextKeyRepo, repo)
		r = setContextValue(r, contextKeyDid, did)
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleLegacySessionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		logger := s.logger.With("name", "handleLegacySessionMiddleware")

		authheader := r.Header.Get("authorization")

		// WebSocket upgrades cannot send custom headers, so the access token
		// is passed as the access_token query parameter instead. Synthesise a
		// Bearer header from it so the rest of the middleware can proceed
		// unchanged.
		if authheader == "" {
			if qt := r.URL.Query().Get("access_token"); qt != "" {
				authheader = "Bearer " + qt
			}
		}

		if authheader == "" {
			s.writeJSON(w, 401, map[string]string{"error": "Unauthorized"})
			return
		}

		pts := strings.Split(authheader, " ")
		if len(pts) != 2 {
			helpers.ServerError(w, nil)
			return
		}

		// move on to oauth session middleware if this is a dpop token
		if pts[0] == "DPoP" {
			next.ServeHTTP(w, r)
			return
		}

		tokenstr := pts[1]
		var token *jwt.Token
		var err error
		token, _, err = new(jwt.Parser).ParseUnverified(tokenstr, jwt.MapClaims{})
		if err != nil {
			helpers.InvalidTokenError(w)
			return
		}
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			helpers.InvalidTokenError(w)
			return
		}

		var did string
		var repo *models.RepoActor

		// service auth tokens
		lxm, hasLxm := claims["lxm"]
		if hasLxm {
			pts := strings.Split(r.URL.String(), "/")
			if lxm != pts[len(pts)-1] {
				logger.Error("service auth lxm incorrect", "lxm", lxm, "expected", pts[len(pts)-1], "error", err)
				helpers.InputError(w, nil)
				return
			}

			maybeDid, ok := claims["iss"].(string)
			if !ok {
				logger.Error("no iss in service auth token", "error", err)
				helpers.InputError(w, nil)
				return
			}
			did = maybeDid

			var maybeRepo *models.RepoActor
			maybeRepo, err = s.getRepoActorByDid(ctx, did)
			if err != nil {
				logger.Error("error fetching repo", "error", err)
				helpers.ServerError(w, nil)
				return
			}
			repo = maybeRepo
		}

		// For service auth tokens (lxm claim), verify using the appropriate key based
		// on compat mode. In compat mode, tokens are signed with ES256K using the user's
		// #atproto key. Otherwise, use ES256 with the PDS server key.
		if hasLxm && repo != nil && repo.CompatMode {
			// Compat mode: verify with user's #atproto key from DID document
			did := syntax.DID(did)
			didDoc, err := s.passport.FetchDoc(ctx, did.String())
			if err != nil {
				logger.Error("unable to resolve did for service auth", "did", did, "error", err)
				helpers.InputError(w, nil)
				return
			}

			verificationMethods := make([]atproto_identity.DocVerificationMethod, len(didDoc.VerificationMethods))
			for i, vm := range didDoc.VerificationMethods {
				verificationMethods[i] = atproto_identity.DocVerificationMethod{
					ID:                 vm.Id,
					Type:               vm.Type,
					PublicKeyMultibase: vm.PublicKeyMultibase,
					Controller:         vm.Controller,
				}
			}
			services := make([]atproto_identity.DocService, len(didDoc.Service))
			for i, svc := range didDoc.Service {
				services[i] = atproto_identity.DocService{
					ID:              svc.Id,
					Type:            svc.Type,
					ServiceEndpoint: svc.ServiceEndpoint,
				}
			}
			parsedIdentity := atproto_identity.ParseIdentity(&atproto_identity.DIDDocument{
				DID:                did,
				AlsoKnownAs:        didDoc.AlsoKnownAs,
				VerificationMethod: verificationMethods,
				Service:            services,
			})

			var key atcrypto.PublicKey
			key, err = parsedIdentity.PublicKey() // use #atproto for compat mode
			if err != nil {
				logger.Error("signing key not found for did", "did", did, "error", err)
				helpers.InputError(w, nil)
				return
			}

			token, err = new(jwt.Parser).Parse(tokenstr, func(t *jwt.Token) (any, error) {
				return key, nil
			})
			if err != nil {
				logger.Error("error parsing jwt", "error", err)
				helpers.ExpiredTokenError(w)
				return
			}
		} else {
			// Non-compat mode or regular access/refresh tokens: use PDS server key (ES256)
			token, err = new(jwt.Parser).Parse(tokenstr, func(t *jwt.Token) (any, error) {
				if _, ok := t.Method.(*jwt.SigningMethodECDSA); !ok {
					return nil, fmt.Errorf("unsupported signing method: %v", t.Header["alg"])
				}
				return &s.privateKey.PublicKey, nil
			})
			if err != nil {
				logger.Error("error parsing jwt", "error", err)
				helpers.ExpiredTokenError(w)
				return
			}
		}

		if !token.Valid {
			helpers.InvalidTokenError(w)
			return
		}

		isRefresh := r.URL.Path == "/xrpc/com.atproto.server.refreshSession"
		scope, _ := claims["scope"].(string)

		if isRefresh && scope != "com.atproto.refresh" {
			helpers.InvalidTokenError(w)
			return
		} else if !hasLxm && !isRefresh && scope != "com.atproto.access" {
			helpers.InvalidTokenError(w)
			return
		}

		table := "tokens"
		if isRefresh {
			table = "refresh_tokens"
		}

		if isRefresh {
			type Result struct {
				Found bool
			}
			var result Result
			if err := s.db.Raw(ctx, "SELECT EXISTS(SELECT 1 FROM "+table+" WHERE token = ?) AS found", nil, tokenstr).Scan(&result).Error; err != nil {
				if err == gorm.ErrRecordNotFound {
					helpers.InvalidTokenError(w)
					return
				}

				logger.Error("error getting token from db", "error", err)
				helpers.ServerError(w, nil)
				return
			}

			if !result.Found {
				helpers.InvalidTokenError(w)
				return
			}
		}

		exp, ok := claims["exp"].(float64)
		if !ok {
			logger.Error("error getting exp from token")
			helpers.ServerError(w, nil)
			return
		}

		if exp < float64(time.Now().UTC().Unix()) {
			helpers.ExpiredTokenError(w)
			return
		}

		if repo == nil {
			maybeRepo, err := s.getRepoActorByDid(ctx, claims["sub"].(string))
			if err != nil {
				logger.Error("error fetching repo", "error", err)
				helpers.ServerError(w, nil)
				return
			}
			repo = maybeRepo
			did = repo.Repo.Did
		}

		r = setContextValue(r, contextKeyRepo, repo)
		r = setContextValue(r, contextKeyDid, did)
		r = setContextValue(r, contextKeyToken, tokenstr)

		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleOauthSessionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		logger := s.logger.With("name", "handleOauthSessionMiddleware")

		authheader := r.Header.Get("authorization")
		if authheader == "" {
			s.writeJSON(w, 401, map[string]string{"error": "Unauthorized"})
			return
		}

		pts := strings.Split(authheader, " ")
		if len(pts) != 2 {
			helpers.ServerError(w, nil)
			return
		}

		if pts[0] != "DPoP" {
			next.ServeHTTP(w, r)
			return
		}

		accessToken := pts[1]

		nonce := s.oauthProvider.NextNonce()
		if nonce != "" {
			w.Header().Set("DPoP-Nonce", nonce)
			w.Header().Add("access-control-expose-headers", "DPoP-Nonce")
		}

		proof, err := s.oauthProvider.DpopManager.CheckProof(r.Method, helpers.RequestURL(r), r.Header, new(accessToken))
		if err != nil {
			if errors.Is(err, dpop.ErrUseDpopNonce) {
				w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
				w.Header().Add("access-control-expose-headers", "WWW-Authenticate")
				s.writeJSON(w, 401, map[string]string{
					"error": "use_dpop_nonce",
				})
				return
			}
			logger.Error("invalid dpop proof", "error", err)
			helpers.InputError(w, nil)
			return
		}
		if proof == nil {
			logger.Error("missing dpop proof")
			helpers.InputError(w, new("missing dpop proof"))
			return
		}

		var oauthToken provider.OauthToken
		if err := s.db.Raw(ctx, "SELECT * FROM oauth_tokens WHERE token = ?", nil, accessToken).Scan(&oauthToken).Error; err != nil {
			logger.Error("error finding access token in db", "error", err)
			helpers.InputError(w, nil)
			return
		}

		if oauthToken.Token == "" {
			helpers.InvalidTokenError(w)
			return
		}

		if oauthToken.Parameters.DpopJkt == nil {
			logger.Error("token not bound to dpop")
			helpers.InputError(w, new("token not bound to dpop"))
			return
		}

		if *oauthToken.Parameters.DpopJkt != proof.JKT {
			logger.Error("jkt mismatch", "token", *oauthToken.Parameters.DpopJkt, "proof", proof.JKT)
			helpers.InputError(w, new("dpop jkt mismatch"))
			return
		}

		if time.Now().After(oauthToken.ExpiresAt) {
			w.Header().Set("WWW-Authenticate", `DPoP error="invalid_token", error_description="Token expired"`)
			w.Header().Add("access-control-expose-headers", "WWW-Authenticate")
			s.writeJSON(w, 401, map[string]string{
				"error":             "invalid_token",
				"error_description": "Token expired",
			})
			return
		}

		repo, err := s.getRepoActorByDid(ctx, oauthToken.Sub)
		if err != nil {
			logger.Error("could not find actor in db", "error", err)
			helpers.ServerError(w, nil)
			return
		}

		logger.Info("oauth middleware fetched repo", "did", repo.Repo.Did, "compatMode", repo.CompatMode)

		r = setContextValue(r, contextKeyRepo, repo)
		r = setContextValue(r, contextKeyDid, repo.Repo.Did)
		r = setContextValue(r, contextKeyToken, accessToken)
		r = setContextValue(r, contextKeyScopes, strings.Split(oauthToken.Parameters.Scope, " "))

		next.ServeHTTP(w, r)
	})
}
