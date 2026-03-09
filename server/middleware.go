package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/golang-jwt/jwt/v4"
	"pkg.rbrt.fr/vow/internal/helpers"
	"pkg.rbrt.fr/vow/models"
	"pkg.rbrt.fr/vow/oauth/dpop"
	"pkg.rbrt.fr/vow/oauth/provider"
	"gitlab.com/yawning/secp256k1-voi"
	secp256k1secec "gitlab.com/yawning/secp256k1-voi/secec"
	"gorm.io/gorm"
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
		if !ok || username != "admin" || password != s.config.AdminPassword {
			helpers.InputError(w, to.StringPtr("Unauthorized"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleLegacySessionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		logger := s.logger.With("name", "handleLegacySessionMiddleware")

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

		// move on to oauth session middleware if this is a dpop token
		if pts[0] == "DPoP" {
			next.ServeHTTP(w, r)
			return
		}

		tokenstr := pts[1]
		token, _, err := new(jwt.Parser).ParseUnverified(tokenstr, jwt.MapClaims{})
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

			maybeRepo, err := s.getRepoActorByDid(ctx, did)
			if err != nil {
				logger.Error("error fetching repo", "error", err)
				helpers.ServerError(w, nil)
				return
			}
			repo = maybeRepo
		}

		if token.Header["alg"] != "ES256K" {
			token, err = new(jwt.Parser).Parse(tokenstr, func(t *jwt.Token) (any, error) {
				if _, ok := t.Method.(*jwt.SigningMethodECDSA); !ok {
					return nil, fmt.Errorf("unsupported signing method: %v", t.Header["alg"])
				}
				return s.privateKey.Public(), nil
			})
			if err != nil {
				logger.Error("error parsing jwt", "error", err)
				helpers.ExpiredTokenError(w)
				return
			}

			if !token.Valid {
				helpers.InvalidTokenError(w)
				return
			}
		} else {
			kpts := strings.Split(tokenstr, ".")
			signingInput := kpts[0] + "." + kpts[1]
			hash := sha256.Sum256([]byte(signingInput))
			sigBytes, err := base64.RawURLEncoding.DecodeString(kpts[2])
			if err != nil {
				logger.Error("error decoding signature bytes", "error", err)
				helpers.ServerError(w, nil)
				return
			}

			if len(sigBytes) != 64 {
				logger.Error("incorrect sigbytes length", "length", len(sigBytes))
				helpers.ServerError(w, nil)
				return
			}

			rBytes := sigBytes[:32]
			sBytes := sigBytes[32:]
			rr, _ := secp256k1.NewScalarFromBytes((*[32]byte)(rBytes))
			ss, _ := secp256k1.NewScalarFromBytes((*[32]byte)(sBytes))

			if repo == nil {
				sub, ok := claims["sub"].(string)
				if !ok {
					s.logger.Error("no sub claim in ES256K token and repo not set")
					helpers.InvalidTokenError(w)
					return
				}
				maybeRepo, err := s.getRepoActorByDid(ctx, sub)
				if err != nil {
					s.logger.Error("error fetching repo for ES256K verification", "error", err)
					helpers.ServerError(w, nil)
					return
				}
				repo = maybeRepo
				did = sub
			}

			sk, err := secp256k1secec.NewPrivateKey(repo.SigningKey)
			if err != nil {
				logger.Error("can't load private key", "error", err)
				helpers.ServerError(w, nil)
				return
			}

			pubKey, ok := sk.Public().(*secp256k1secec.PublicKey)
			if !ok {
				logger.Error("error getting public key from sk")
				helpers.ServerError(w, nil)
				return
			}

			verified := pubKey.VerifyRaw(hash[:], rr, ss)
			if !verified {
				logger.Error("error verifying", "error", err)
				helpers.ServerError(w, nil)
				return
			}
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
			logger.Error("error getting iat from token")
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

		proof, err := s.oauthProvider.DpopManager.CheckProof(r.Method, "https://"+s.config.Hostname+r.URL.String(), r.Header, to.StringPtr(accessToken))
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

		if *oauthToken.Parameters.DpopJkt != proof.JKT {
			logger.Error("jkt mismatch", "token", oauthToken.Parameters.DpopJkt, "proof", proof.JKT)
			helpers.InputError(w, to.StringPtr("dpop jkt mismatch"))
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

		r = setContextValue(r, contextKeyRepo, repo)
		r = setContextValue(r, contextKeyDid, repo.Repo.Did)
		r = setContextValue(r, contextKeyToken, accessToken)
		r = setContextValue(r, contextKeyScopes, strings.Split(oauthToken.Parameters.Scope, " "))

		next.ServeHTTP(w, r)
	})
}
