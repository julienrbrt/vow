package server

import (
	"context"
	"crypto/ecdsa"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/smtp"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/bluesky-social/indigo/api/atproto"
	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/bluesky-social/indigo/events"
	"github.com/bluesky-social/indigo/util"
	"github.com/bluesky-social/indigo/xrpc"
	"github.com/domodwyer/mailyak/v3"
	"github.com/glebarez/sqlite"
	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/go-playground/validator"
	"github.com/gorilla/sessions"
	"github.com/ipfs/go-cid"
	"github.com/ipfs/kubo/client/rpc"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"pkg.rbrt.fr/vow/identity"
	"pkg.rbrt.fr/vow/internal/db"
	"pkg.rbrt.fr/vow/internal/helpers"
	"pkg.rbrt.fr/vow/models"
	"pkg.rbrt.fr/vow/oauth/client"
	"pkg.rbrt.fr/vow/oauth/constants"
	"pkg.rbrt.fr/vow/oauth/dpop"
	"pkg.rbrt.fr/vow/oauth/provider"
	"pkg.rbrt.fr/vow/plc"

	"gorm.io/gorm"
)

const (
	AccountSessionMaxAge = 30 * 24 * time.Hour
)

// IPFSConfig holds configuration for the IPFS node that the PDS runs
// alongside. All repo blocks and blob data are stored on and retrieved from
// the co-located Kubo node — SQLite is used only for relational metadata
// (accounts, sessions, records index, etc.), not for content.
type IPFSConfig struct {
	// NodeURL is the base URL of the Kubo RPC API, e.g. "http://ipfs:5001"
	// in Docker or "http://127.0.0.1:5001" locally.
	NodeURL string

	// GatewayURL is the public-facing IPFS gateway used to serve blobs, e.g.
	// "http://ipfs:8080" or "https://ipfs.io". When set, sync.getBlob
	// redirects clients to the gateway instead of proxying through vow.
	GatewayURL string
}

type Server struct {
	http       *http.Client
	httpd      *http.Server
	mail       *mailyak.MailYak
	mailLk     *sync.Mutex
	router     *chi.Mux
	db         *db.DB
	plcClient  *plc.Client
	logger     *slog.Logger
	config     *config
	privateKey *ecdsa.PrivateKey
	// privateKeyATP is the same JWK key wrapped as an atcrypto.PrivateKeyP256
	// so it can be passed directly to atcrypto signing functions. Used to sign
	// service-auth JWTs on behalf of the user (atproto_service slot in DID doc).
	privateKeyATP *atcrypto.PrivateKeyP256
	repoman       *RepoMan
	oauthProvider *provider.Provider
	evtman        *events.EventManager
	passport      *identity.Passport
	signerHub     *SignerHub

	sessions         *sessions.CookieStore
	validator        *validator.Validate
	templateRenderer *TemplateRenderer

	lastRequestCrawl time.Time
	requestCrawlMu   sync.Mutex

	dbName     string
	ipfsConfig *IPFSConfig
	ipfsAPI    *rpc.HttpApi
}

type Args struct {
	Logger *slog.Logger

	Addr            string
	DbName          string
	Version         string
	Did             string
	Hostname        string
	RotationKeyPath string
	JwkPath         string
	ContactEmail    string
	Relays          []string
	AdminPassword   string
	RequireInvite   bool

	SmtpUser  string
	SmtpPass  string
	SmtpHost  string
	SmtpPort  string
	SmtpEmail string
	SmtpName  string

	IPFSConfig *IPFSConfig

	SessionSecret    string
	SessionCookieKey string

	FallbackProxy string
}

type config struct {
	Version          string
	Did              string
	Hostname         string
	ContactEmail     string
	EnforcePeering   bool
	Relays           []string
	AdminPassword    string
	RequireInvite    bool
	SmtpEmail        string
	SmtpName         string
	SessionCookieKey string
	FallbackProxy    string
}

type CustomValidator struct {
	validator *validator.Validate
}

type ValidationError struct {
	error
	Field string
	Tag   string
}

func (cv *CustomValidator) Validate(i any) error {
	if err := cv.validator.Struct(i); err != nil {
		var validateErrors validator.ValidationErrors
		if errors.As(err, &validateErrors) && len(validateErrors) > 0 {
			first := validateErrors[0]
			return ValidationError{
				error: err,
				Field: first.Field(),
				Tag:   first.Tag(),
			}
		}

		return err
	}

	return nil
}

//go:embed templates/*
var templateFS embed.FS

//go:embed static/*
var staticFS embed.FS

type TemplateRenderer struct {
	templates    *template.Template
	isDev        bool
	templatePath string
}

func (s *Server) loadTemplates() {
	absPath, _ := filepath.Abs("server/templates/*.html")
	if s.config.Version == "dev" {
		tmpl := template.Must(template.ParseGlob(absPath))
		s.templateRenderer = &TemplateRenderer{
			templates:    tmpl,
			isDev:        true,
			templatePath: absPath,
		}
	} else {
		tmpl := template.Must(template.ParseFS(templateFS, "templates/*.html"))
		s.templateRenderer = &TemplateRenderer{
			templates: tmpl,
			isDev:     false,
		}
	}
}

func (t *TemplateRenderer) Render(w io.Writer, name string, data any) error {
	if t.isDev {
		tmpl, err := template.ParseGlob(t.templatePath)
		if err != nil {
			return err
		}
		t.templates = tmpl
	}

	return t.templates.ExecuteTemplate(w, name, data)
}

// renderTemplate is a convenience method on the server that renders a named
// HTML template to the given ResponseWriter with a 200 status.
func (s *Server) renderTemplate(w http.ResponseWriter, name string, data any) error {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	return s.templateRenderer.Render(w, name, data)
}

// writeJSON writes a JSON-encoded value with the given status code.
func (s *Server) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		s.logger.Error("failed to encode JSON response", "error", err)
	}
}

func New(args *Args) (*Server, error) {
	if args.Logger == nil {
		args.Logger = slog.Default()
	}

	logger := args.Logger.With("name", "New")

	if args.Addr == "" {
		return nil, fmt.Errorf("addr must be set")
	}

	if args.DbName == "" {
		return nil, fmt.Errorf("db name must be set")
	}

	if args.Did == "" {
		return nil, fmt.Errorf("vow did must be set")
	}

	if args.ContactEmail == "" {
		return nil, fmt.Errorf("vow contact email is required")
	}

	if _, err := syntax.ParseDID(args.Did); err != nil {
		return nil, fmt.Errorf("error parsing vow did: %w", err)
	}

	if args.Hostname == "" {
		return nil, fmt.Errorf("vow hostname must be set")
	}

	if args.AdminPassword == "" {
		return nil, fmt.Errorf("admin password must be set")
	}

	if args.SessionSecret == "" {
		return nil, fmt.Errorf("session secret is required")
	}

	r := chi.NewRouter()

	r.Use(chimiddleware.StripSlashes)
	r.Use(func(next http.Handler) http.Handler {
		logger := args.Logger.With("component", "http")
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r)
			logger.Info("request", "method", r.Method, "path", r.URL.Path, "remote_addr", r.RemoteAddr)
		})
	})
	r.Use(corsMiddleware)

	vdtor := validator.New()
	if err := vdtor.RegisterValidation("atproto-handle", func(fl validator.FieldLevel) bool {
		if _, err := syntax.ParseHandle(fl.Field().String()); err != nil {
			return false
		}
		return true
	}); err != nil {
		return nil, fmt.Errorf("failed to register atproto-handle validator: %w", err)
	}
	if err := vdtor.RegisterValidation("atproto-did", func(fl validator.FieldLevel) bool {
		if _, err := syntax.ParseDID(fl.Field().String()); err != nil {
			return false
		}
		return true
	}); err != nil {
		return nil, fmt.Errorf("failed to register atproto-did validator: %w", err)
	}
	if err := vdtor.RegisterValidation("atproto-rkey", func(fl validator.FieldLevel) bool {
		if _, err := syntax.ParseRecordKey(fl.Field().String()); err != nil {
			return false
		}
		return true
	}); err != nil {
		return nil, fmt.Errorf("failed to register atproto-rkey validator: %w", err)
	}
	if err := vdtor.RegisterValidation("atproto-nsid", func(fl validator.FieldLevel) bool {
		if _, err := syntax.ParseNSID(fl.Field().String()); err != nil {
			return false
		}
		return true
	}); err != nil {
		return nil, fmt.Errorf("failed to register atproto-nsid validator: %w", err)
	}

	httpd := &http.Server{
		Addr:    args.Addr,
		Handler: r,
		// Extended timeouts to accommodate repo imports and large blob uploads.
		ReadTimeout:  5 * time.Minute,
		WriteTimeout: 5 * time.Minute,
		IdleTimeout:  5 * time.Minute,
	}

	var gdb *gorm.DB
	var err error
	gdb, err = gorm.Open(sqlite.Open(args.DbName), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}
	if err := gdb.Exec("PRAGMA journal_mode=WAL").Error; err != nil {
		return nil, fmt.Errorf("failed to set journal_mode=WAL: %w", err)
	}
	if err := gdb.Exec("PRAGMA synchronous=NORMAL").Error; err != nil {
		return nil, fmt.Errorf("failed to set synchronous=NORMAL: %w", err)
	}
	logger.Info("connected to SQLite database", "path", args.DbName)
	dbw := db.NewDB(gdb)

	rkbytes, err := os.ReadFile(args.RotationKeyPath)
	if err != nil {
		return nil, err
	}

	jwkbytes, err := os.ReadFile(args.JwkPath)
	if err != nil {
		return nil, err
	}

	key, err := helpers.ParseJWKFromBytes(jwkbytes)
	if err != nil {
		return nil, err
	}

	var pkey ecdsa.PrivateKey
	if err := key.Raw(&pkey); err != nil {
		return nil, err
	}

	// Wrap the JWK private key as an atcrypto.PrivateKeyP256 for ATProto-compatible
	// signing. Convert via ecdh to get the raw private key bytes.
	ecdhKey, err := pkey.ECDH()
	if err != nil {
		return nil, fmt.Errorf("converting private key to ecdh: %w", err)
	}
	atpKey, err := atcrypto.ParsePrivateBytesP256(ecdhKey.Bytes())
	if err != nil {
		return nil, fmt.Errorf("wrapping JWK private key for atcrypto: %w", err)
	}

	h := util.RobustHTTPClient()

	plcClient, err := plc.NewClient(&plc.ClientArgs{
		H:              h,
		Service:        "https://plc.directory",
		PdsHostname:    args.Hostname,
		RotationKey:    rkbytes,
		ServiceAuthKey: atpKey,
	})
	if err != nil {
		return nil, err
	}

	oauthCli := &http.Client{
		Timeout: 10 * time.Second,
	}

	var nonceSecret []byte
	maybeSecret, err := os.ReadFile("nonce.secret")
	if err != nil && !os.IsNotExist(err) {
		logger.Error("error attempting to read nonce secret", "error", err)
	} else {
		nonceSecret = maybeSecret
	}

	evtPersister, err := NewDbPersister(gdb, 72*time.Hour)
	if err != nil {
		return nil, fmt.Errorf("failed to create event persister: %w", err)
	}

	ipfsHTTPClient := &http.Client{
		Timeout: 30 * time.Second,
	}
	ipfsAPI, err := rpc.NewURLApiWithClient(args.IPFSConfig.NodeURL, ipfsHTTPClient)
	if err != nil {
		return nil, fmt.Errorf("failed to create IPFS client: %w", err)
	}

	cookieStore := sessions.NewCookieStore([]byte(args.SessionSecret))

	s := &Server{
		http:          h,
		httpd:         httpd,
		router:        r,
		logger:        args.Logger,
		db:            dbw,
		plcClient:     plcClient,
		privateKey:    &pkey,
		privateKeyATP: atpKey,
		sessions:      cookieStore,
		validator:     vdtor,
		config: &config{
			Version:          args.Version,
			Did:              args.Did,
			Hostname:         args.Hostname,
			ContactEmail:     args.ContactEmail,
			EnforcePeering:   false,
			Relays:           args.Relays,
			AdminPassword:    args.AdminPassword,
			RequireInvite:    args.RequireInvite,
			SmtpName:         args.SmtpName,
			SmtpEmail:        args.SmtpEmail,
			SessionCookieKey: args.SessionCookieKey,
			FallbackProxy:    args.FallbackProxy,
		},
		signerHub: NewSignerHub(),
		evtman:    events.NewEventManager(evtPersister),
		passport:  identity.NewPassport(h, identity.NewMemCache(10_000)),

		dbName:     args.DbName,
		ipfsConfig: args.IPFSConfig,
		ipfsAPI:    ipfsAPI,

		oauthProvider: provider.NewProvider(provider.Args{
			Hostname: args.Hostname,
			ClientManagerArgs: client.ManagerArgs{
				Cli:    oauthCli,
				Logger: args.Logger.With("component", "oauth-client-manager"),
			},
			DpopManagerArgs: dpop.ManagerArgs{
				NonceSecret:           nonceSecret,
				NonceRotationInterval: constants.NonceMaxRotationInterval / 3,
				OnNonceSecretCreated: func(newNonce []byte) {
					if err := os.WriteFile("nonce.secret", newNonce, 0644); err != nil {
						logger.Error("error writing new nonce secret", "error", err)
					}
				},
				Logger:   args.Logger.With("component", "dpop-manager"),
				Hostname: args.Hostname,
			},
		}),
	}

	s.loadTemplates()

	s.repoman = NewRepoMan(s)

	// TODO: should validate these args
	if args.SmtpUser == "" || args.SmtpPass == "" || args.SmtpHost == "" || args.SmtpPort == "" || args.SmtpEmail == "" || args.SmtpName == "" {
		args.Logger.Warn("not enough smtp args were provided. mailing will not work for your server.")
	} else {
		mail := mailyak.New(args.SmtpHost+":"+args.SmtpPort, smtp.PlainAuth("", args.SmtpUser, args.SmtpPass, args.SmtpHost))
		mail.From(s.config.SmtpEmail)
		mail.FromName(s.config.SmtpName)

		s.mail = mail
		s.mailLk = &sync.Mutex{}
	}

	return s, nil
}

// corsMiddleware adds permissive CORS headers to every response.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		w.Header().Set("Access-Control-Allow-Methods", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Expose-Headers", "Atproto-Proxy-Type,Atproto-Repo-Rev,Atproto-Content-Type,Content-Type,Content-Length,WWW-Authenticate,DPoP-Nonce,X-Ratelimit-Limit,X-Ratelimit-Remaining,X-Ratelimit-Reset")
		w.Header().Set("Access-Control-Max-Age", "100000000")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) addRoutes() {
	r := s.router

	// static
	if s.config.Version == "dev" {
		r.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.Dir("server/static"))))
	} else {
		r.Handle("/static/*", http.FileServer(http.FS(staticFS)))
	}

	// metrics
	r.Handle("/metrics", promhttp.Handler())

	// random stuff
	r.Get("/", s.handleRoot)
	r.Get("/xrpc/_health", s.handleHealth)
	r.Get("/.well-known/did.json", s.handleWellKnown)
	r.Get("/.well-known/atproto-did", s.handleAtprotoDid)
	r.Get("/.well-known/oauth-protected-resource", s.handleOauthProtectedResource)
	r.Get("/.well-known/oauth-authorization-server", s.handleOauthAuthorizationServer)
	r.Get("/robots.txt", s.handleRobots)

	// public
	r.Get("/xrpc/com.atproto.identity.resolveHandle", s.handleResolveHandle)
	r.Post("/xrpc/com.atproto.server.createAccount", s.handleCreateAccount)
	r.Post("/xrpc/com.atproto.server.createSession", s.handleCreateSession)
	r.Get("/xrpc/com.atproto.server.describeServer", s.handleDescribeServer)

	r.Get("/xrpc/com.atproto.repo.describeRepo", s.handleDescribeRepo)
	r.Get("/xrpc/com.atproto.sync.listRepos", s.handleListRepos)
	r.Get("/xrpc/com.atproto.repo.listRecords", s.handleListRecords)
	r.Get("/xrpc/com.atproto.repo.getRecord", s.handleRepoGetRecord)
	r.Get("/xrpc/com.atproto.sync.getRecord", s.handleSyncGetRecord)
	r.Get("/xrpc/com.atproto.sync.getBlocks", s.handleGetBlocks)
	r.Get("/xrpc/com.atproto.sync.getLatestCommit", s.handleSyncGetLatestCommit)
	r.Get("/xrpc/com.atproto.sync.getRepoStatus", s.handleSyncGetRepoStatus)
	r.Get("/xrpc/com.atproto.sync.getRepo", s.handleSyncGetRepo)
	r.Get("/xrpc/com.atproto.sync.subscribeRepos", s.handleSyncSubscribeRepos)
	r.Get("/xrpc/com.atproto.sync.listBlobs", s.handleSyncListBlobs)
	r.Get("/xrpc/com.atproto.sync.getBlob", s.handleSyncGetBlob)

	// labels
	r.Get("/xrpc/com.atproto.label.queryLabels", s.handleLabelQueryLabels)

	// account
	r.Get("/account", s.handleAccount)
	r.Post("/account/revoke", s.handleAccountRevoke)
	r.Get("/account/signin", s.handleAccountSigninGet)
	r.Post("/account/signin", s.handleAccountSigninPost)
	r.Get("/account/signup", s.handleAccountSignupGet)
	r.Post("/account/signup", s.handleAccountSignupPost)
	r.Get("/account/signout", s.handleAccountSignout)
	r.With(s.handleWebSessionMiddleware).Post("/account/supply-signing-key", s.handleSupplySigningKey)
	r.With(s.handleWebSessionMiddleware).Post("/account/passkey-challenge", s.handlePasskeyChallenge)
	r.With(s.handleWebSessionMiddleware).Post("/account/passkey-assertion-challenge", s.handlePasskeyAssertionChallenge)
	r.With(s.handleWebSessionMiddleware).Post("/account/delete", s.handleAccountDelete)
	r.Get("/account/signer", s.handleAccountSigner)
	r.With(s.handleWebSessionMiddleware).Post("/account/compat", s.handleAccountUpdateCompat)

	// oauth account
	r.Get("/oauth/jwks", s.handleOauthJwks)
	r.Get("/oauth/authorize", s.handleOauthAuthorizeGet)
	r.Post("/oauth/authorize", s.handleOauthAuthorizePost)

	// oauth authorization (with BaseMiddleware)
	r.With(s.oauthProvider.BaseMiddleware).Post("/oauth/par", s.handleOauthPar)
	r.With(s.oauthProvider.BaseMiddleware).Post("/oauth/token", s.handleOauthToken)

	// authed
	authed := func(h http.HandlerFunc) http.Handler {
		return s.handleLegacySessionMiddleware(s.handleOauthSessionMiddleware(h))
	}

	r.Get("/xrpc/com.atproto.server.getSession", authed(s.handleGetSession).ServeHTTP)
	r.Post("/xrpc/com.atproto.server.refreshSession", authed(s.handleRefreshSession).ServeHTTP)
	r.Post("/xrpc/com.atproto.server.deleteSession", authed(s.handleDeleteSession).ServeHTTP)
	r.Get("/xrpc/com.atproto.identity.getRecommendedDidCredentials", authed(s.handleGetRecommendedDidCredentials).ServeHTTP)
	r.Post("/xrpc/com.atproto.identity.updateHandle", authed(s.handleIdentityUpdateHandle).ServeHTTP)
	r.Post("/xrpc/com.atproto.identity.requestPlcOperationSignature", authed(s.handleIdentityRequestPlcOperationSignature).ServeHTTP)
	r.Post("/xrpc/com.atproto.identity.signPlcOperation", authed(s.handleSignPlcOperation).ServeHTTP)
	r.Post("/xrpc/com.atproto.identity.submitPlcOperation", authed(s.handleSubmitPlcOperation).ServeHTTP)
	r.Post("/xrpc/com.atproto.server.confirmEmail", authed(s.handleServerConfirmEmail).ServeHTTP)
	r.Post("/xrpc/com.atproto.server.requestEmailConfirmation", authed(s.handleServerRequestEmailConfirmation).ServeHTTP)
	r.Post("/xrpc/com.atproto.server.requestPasswordReset", s.handleServerRequestPasswordReset) // AUTH NOT REQUIRED FOR THIS ONE
	r.Post("/xrpc/com.atproto.server.requestEmailUpdate", authed(s.handleServerRequestEmailUpdate).ServeHTTP)
	r.Post("/xrpc/com.atproto.server.resetPassword", authed(s.handleServerResetPassword).ServeHTTP)
	r.Post("/xrpc/com.atproto.server.updateEmail", authed(s.handleServerUpdateEmail).ServeHTTP)
	r.Get("/xrpc/com.atproto.server.getAccountInviteCodes", authed(s.handleGetAccountInviteCodes).ServeHTTP)
	r.Get("/xrpc/com.atproto.server.getServiceAuth", authed(s.handleServerGetServiceAuth).ServeHTTP)
	r.Get("/xrpc/com.atproto.server.checkAccountStatus", authed(s.handleServerCheckAccountStatus).ServeHTTP)
	r.Post("/xrpc/com.atproto.server.deactivateAccount", authed(s.handleServerDeactivateAccount).ServeHTTP)
	r.Post("/xrpc/com.atproto.server.activateAccount", authed(s.handleServerActivateAccount).ServeHTTP)
	r.Post("/xrpc/com.atproto.server.requestAccountDelete", authed(s.handleServerRequestAccountDelete).ServeHTTP)
	r.Post("/xrpc/com.atproto.server.deleteAccount", s.handleServerDeleteAccount)

	// BYOK (Bring Your Own Key) — the browser-based signer registers the
	// public key and connects for real-time signing over WebSocket.
	r.Post("/xrpc/com.atproto.server.supplySigningKey", authed(s.handleSupplySigningKey).ServeHTTP)
	r.Get("/xrpc/com.atproto.server.getSigningKey", authed(s.handleGetSigningKey).ServeHTTP)
	r.Get("/xrpc/com.atproto.server.signerConnect", authed(s.handleSignerConnect).ServeHTTP)

	// repo
	r.Get("/xrpc/com.atproto.repo.listMissingBlobs", authed(s.handleListMissingBlobs).ServeHTTP)
	r.Post("/xrpc/com.atproto.repo.createRecord", authed(s.handleCreateRecord).ServeHTTP)
	r.Post("/xrpc/com.atproto.repo.putRecord", authed(s.handlePutRecord).ServeHTTP)
	r.Post("/xrpc/com.atproto.repo.deleteRecord", authed(s.handleDeleteRecord).ServeHTTP)
	r.Post("/xrpc/com.atproto.repo.applyWrites", authed(s.handleApplyWrites).ServeHTTP)
	r.Post("/xrpc/com.atproto.repo.uploadBlob", authed(s.handleRepoUploadBlob).ServeHTTP)
	r.Post("/xrpc/com.atproto.repo.importRepo", authed(s.handleRepoImportRepo).ServeHTTP)

	// stupid silly endpoints
	r.Get("/xrpc/app.bsky.actor.getPreferences", authed(s.handleActorGetPreferences).ServeHTTP)
	r.Post("/xrpc/app.bsky.actor.putPreferences", authed(s.handleActorPutPreferences).ServeHTTP)
	r.Get("/xrpc/app.bsky.feed.getFeed", authed(s.handleProxyBskyFeedGetFeed).ServeHTTP)
	r.Get("/xrpc/app.bsky.ageassurance.getState", authed(s.handleAgeAssurance).ServeHTTP)

	// admin routes
	r.With(s.handleAdminMiddleware).Post("/xrpc/com.atproto.server.createInviteCode", s.handleCreateInviteCode)
	r.With(s.handleAdminMiddleware).Post("/xrpc/com.atproto.server.createInviteCodes", s.handleCreateInviteCodes)

	// catch-all proxy (authed)
	r.Get("/xrpc/*", authed(s.handleProxy).ServeHTTP)
	r.Post("/xrpc/*", authed(s.handleProxy).ServeHTTP)
}

func (s *Server) Serve(ctx context.Context) error {
	logger := s.logger.With("name", "Serve")

	s.addRoutes()

	logger.Info("migrating...")

	if err := s.db.AutoMigrate(
		&models.Actor{},
		&models.Repo{},
		&models.InviteCode{},
		&models.InviteCodeUse{},

		&models.Token{},
		&models.RefreshToken{},
		&models.Record{},
		&models.Blob{},
		&provider.OauthToken{},
		&provider.OauthAuthorizationRequest{},
	); err != nil {
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	logger.Info("starting vow")

	go func() {
		if err := s.httpd.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("http server stopped unexpectedly", "err", err)
		}
	}()

	go func() {
		if err := s.requestCrawl(ctx); err != nil {
			logger.Error("error requesting crawls", "err", err)
		}
	}()

	<-ctx.Done()

	s.logger.Info("shut down")

	return nil
}

func (s *Server) requestCrawl(ctx context.Context) error {
	logger := s.logger.With("component", "request-crawl")
	s.requestCrawlMu.Lock()
	defer s.requestCrawlMu.Unlock()

	logger.Info("requesting crawl with configured relays")

	if time.Since(s.lastRequestCrawl) <= 1*time.Minute {
		return fmt.Errorf("a crawl request has already been made within the last minute")
	}

	for _, relay := range s.config.Relays {
		logger := logger.With("relay", relay)
		logger.Info("requesting crawl from relay")
		cli := xrpc.Client{Host: relay}
		if err := atproto.SyncRequestCrawl(ctx, &cli, &atproto.SyncRequestCrawl_Input{
			Hostname: s.config.Hostname,
		}); err != nil {
			logger.Error("error requesting crawl", "err", err)
		} else {
			logger.Info("crawl requested successfully")
		}
	}

	s.lastRequestCrawl = time.Now()

	return nil
}

func (s *Server) UpdateRepo(ctx context.Context, did string, root cid.Cid, rev string) error {
	if err := s.db.Exec(ctx, "UPDATE repos SET root = ?, rev = ? WHERE did = ?", nil, root.Bytes(), rev, did).Error; err != nil {
		return err
	}

	return nil
}
