package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	_ "net/http/pprof"
	"os"
	"strings"
	"time"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/glebarez/sqlite"
	_ "github.com/joho/godotenv/autoload"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"pkg.rbrt.fr/vow/internal/helpers"
	"pkg.rbrt.fr/vow/server"
)

var Version = "dev"

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:           "vow",
	Short:         "An atproto PDS",
	Version:       Version,
	SilenceErrors: true,
	SilenceUsage:  true,
}

func init() {
	pf := rootCmd.PersistentFlags()

	pf.String(flagAddr, ":8080", "Listen address")
	pf.String(flagDbName, "vow.db", "SQLite database file path")
	pf.String(flagDid, "", "DID of this PDS")
	pf.String(flagHostname, "", "Public hostname of this PDS")
	pf.String(flagRotationKeyPath, "", "Path to the rotation key file")
	pf.String(flagJwkPath, "", "Path to the private JWK file")
	pf.String(flagContactEmail, "", "Contact e-mail address for this PDS")
	pf.StringSlice(flagRelays, []string{}, "Relay URLs to crawl")
	pf.String(flagAdminPassword, "", "Admin password")
	pf.Bool(flagRequireInvite, true, "Require an invite code to create an account")
	pf.String(flagSmtpUser, "", "SMTP username")
	pf.String(flagSmtpPass, "", "SMTP password")
	pf.String(flagSmtpHost, "", "SMTP host")
	pf.String(flagSmtpPort, "", "SMTP port")
	pf.String(flagSmtpEmail, "", "SMTP from address")
	pf.String(flagSmtpName, "", "SMTP from name")
	pf.Bool(flagIpfsBlobstoreEnabled, false, "Store blobs on IPFS via the Kubo HTTP RPC API instead of SQLite")
	pf.String(flagIpfsNodeUrl, "http://127.0.0.1:5001", "Base URL of the Kubo (go-ipfs) RPC API used for adding and fetching blobs")
	pf.String(flagIpfsGatewayUrl, "", "Public IPFS gateway URL for blob redirects (e.g. https://ipfs.io). When set, getBlob redirects to this URL instead of proxying through the node")
	pf.String(flagIpfsPinningServiceUrl, "", "Remote IPFS Pinning Service API endpoint (e.g. https://api.pinata.cloud/psa). Leave empty to skip remote pinning")
	pf.String(flagIpfsPinningServiceToken, "", "Bearer token for authenticating with the remote IPFS pinning service")
	pf.String(flagSessionSecret, "", "Session secret")
	pf.String(flagSessionCookieKey, "session", "Session cookie key name")

	pf.String(flagFallbackProxy, "", "Fallback proxy URL")
	pf.String(flagLogLevel, "info", "Log level: debug, info, warn, error")
	pf.Bool(flagDebug, false, "Enable debug logging (shorthand for --log-level=debug)")
	pf.String(flagMetricsListenAddress, "0.0.0.0:6009", "Listen address for the Prometheus metrics / pprof endpoint")

	v := viper.New()
	v.SetEnvPrefix("VOW")
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	v.AutomaticEnv()
	_ = v.BindEnv(flagDebug, "DEBUG")
	_ = v.BindEnv(flagLogLevel, "VOW_LOG_LEVEL", "LOG_LEVEL")
	_ = v.BindEnv(flagMetricsListenAddress, "METRICS_LISTEN_ADDRESS")
	_ = v.BindPFlags(pf)

	rootCmd.AddCommand(
		newServeCmd(v),
		newCreateRotationKeyCmd(),
		newCreatePrivateJwkCmd(),
		newCreateInviteCodeCmd(v),
		newResetPasswordCmd(v),
	)
}

func buildLogger(v *viper.Viper) *slog.Logger {
	var level slog.Level
	if v.GetBool(flagDebug) {
		level = slog.LevelDebug
	} else {
		switch strings.ToLower(v.GetString(flagLogLevel)) {
		case "debug":
			level = slog.LevelDebug
		case "warn":
			level = slog.LevelWarn
		case "error":
			level = slog.LevelError
		default:
			level = slog.LevelInfo
		}
	}

	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level:     level,
		AddSource: true,
	})
	logger := slog.New(handler)
	slog.SetDefault(logger)
	return logger
}

func startMetrics(v *viper.Viper) {
	addr := v.GetString(flagMetricsListenAddress)
	if addr == "" {
		return
	}
	logger := slog.Default().With("component", "telemetry")
	logger.Info("starting metrics server", "address", addr)
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.Handle("/debug/pprof/", http.DefaultServeMux)
	go func() {
		if err := http.ListenAndServe(addr, mux); err != nil {
			logger.Error("metrics server failed", "err", err)
		}
	}()
}

func newDb(v *viper.Viper) (*gorm.DB, error) {
	dbName := v.GetString(flagDbName)
	if dbName == "" {
		dbName = "vow.db"
	}
	return gorm.Open(sqlite.Open(dbName), &gorm.Config{})
}

func newServeCmd(v *viper.Viper) *cobra.Command {
	return &cobra.Command{
		Use:   "run",
		Short: "Start the vow PDS",
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := buildLogger(v)
			startMetrics(v)

			s, err := server.New(&server.Args{
				Logger:          logger,
				Addr:            v.GetString(flagAddr),
				DbName:          v.GetString(flagDbName),
				Did:             v.GetString(flagDid),
				Hostname:        v.GetString(flagHostname),
				RotationKeyPath: v.GetString(flagRotationKeyPath),
				JwkPath:         v.GetString(flagJwkPath),
				ContactEmail:    v.GetString(flagContactEmail),
				Version:         Version,
				Relays:          v.GetStringSlice(flagRelays),
				AdminPassword:   v.GetString(flagAdminPassword),
				RequireInvite:   v.GetBool(flagRequireInvite),
				SmtpUser:        v.GetString(flagSmtpUser),
				SmtpPass:        v.GetString(flagSmtpPass),
				SmtpHost:        v.GetString(flagSmtpHost),
				SmtpPort:        v.GetString(flagSmtpPort),
				SmtpEmail:       v.GetString(flagSmtpEmail),
				SmtpName:        v.GetString(flagSmtpName),
				IPFSConfig: &server.IPFSConfig{
					BlobstoreEnabled:    v.GetBool(flagIpfsBlobstoreEnabled),
					NodeURL:             v.GetString(flagIpfsNodeUrl),
					GatewayURL:          v.GetString(flagIpfsGatewayUrl),
					PinningServiceURL:   v.GetString(flagIpfsPinningServiceUrl),
					PinningServiceToken: v.GetString(flagIpfsPinningServiceToken),
				},
				SessionSecret:    v.GetString(flagSessionSecret),
				SessionCookieKey: v.GetString(flagSessionCookieKey),

				FallbackProxy: v.GetString(flagFallbackProxy),
			})
			if err != nil {
				return fmt.Errorf("error creating vow: %w", err)
			}

			if err := s.Serve(context.Background()); err != nil {
				return fmt.Errorf("error starting vow: %w", err)
			}

			return nil
		},
	}
}

func newCreateRotationKeyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create-rotation-key",
		Short: "Create a rotation key for your PDS",
		RunE: func(cmd *cobra.Command, args []string) error {
			out, _ := cmd.Flags().GetString("out")

			key, err := atcrypto.GeneratePrivateKeyK256()
			if err != nil {
				return err
			}

			if err := os.WriteFile(out, key.Bytes(), 0644); err != nil {
				return err
			}

			fmt.Printf("Rotation key written to %s\n", out)
			return nil
		},
	}

	cmd.Flags().StringP("out", "o", "", "Output file for the rotation key (required)")
	_ = cmd.MarkFlagRequired("out")

	return cmd
}

func newCreatePrivateJwkCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create-private-jwk",
		Short: "Create a private JWK for your PDS",
		RunE: func(cmd *cobra.Command, args []string) error {
			out, _ := cmd.Flags().GetString("out")

			privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				return err
			}

			key, err := jwk.FromRaw(privKey)
			if err != nil {
				return err
			}

			if err := key.Set(jwk.KeyIDKey, fmt.Sprintf("%d", time.Now().Unix())); err != nil {
				return err
			}

			b, err := json.Marshal(key)
			if err != nil {
				return err
			}

			if err := os.WriteFile(out, b, 0644); err != nil {
				return err
			}

			fmt.Printf("Private JWK written to %s\n", out)
			return nil
		},
	}

	cmd.Flags().StringP("out", "o", "", "Output file for the private JWK (required)")
	_ = cmd.MarkFlagRequired("out")

	return cmd
}

func newCreateInviteCodeCmd(v *viper.Viper) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create-invite-code",
		Short: "Create an invite code",
		RunE: func(cmd *cobra.Command, args []string) error {
			db, err := newDb(v)
			if err != nil {
				return err
			}

			forFlag, _ := cmd.Flags().GetString("for")
			uses, _ := cmd.Flags().GetInt("uses")

			forDid := "did:plc:123"
			if forFlag != "" {
				did, err := syntax.ParseDID(forFlag)
				if err != nil {
					return fmt.Errorf("invalid DID %q: %w", forFlag, err)
				}
				forDid = did.String()
			}

			code := fmt.Sprintf("%s-%s", helpers.RandomVarchar(8), helpers.RandomVarchar(8))

			if err := db.Exec(
				"INSERT INTO invite_codes (did, code, remaining_use_count) VALUES (?, ?, ?)",
				forDid, code, uses,
			).Error; err != nil {
				return err
			}

			fmt.Printf("New invite code created with %d uses: %s\n", uses, code)
			return nil
		},
	}

	cmd.Flags().String("for", "", "Optional DID to assign the invite code to")
	cmd.Flags().Int("uses", 1, "Number of times the invite code can be used")

	return cmd
}

func newResetPasswordCmd(v *viper.Viper) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "reset-password",
		Short: "Reset a user's password",
		RunE: func(cmd *cobra.Command, args []string) error {
			db, err := newDb(v)
			if err != nil {
				return err
			}

			didStr, _ := cmd.Flags().GetString("did")
			did, err := syntax.ParseDID(didStr)
			if err != nil {
				return fmt.Errorf("invalid DID %q: %w", didStr, err)
			}

			newPass := fmt.Sprintf("%s-%s", helpers.RandomVarchar(12), helpers.RandomVarchar(12))
			hashed, err := bcrypt.GenerateFromPassword([]byte(newPass), 10)
			if err != nil {
				return err
			}

			if err := db.Exec(
				"UPDATE repos SET password = ? WHERE did = ?",
				hashed, did.String(),
			).Error; err != nil {
				return err
			}

			fmt.Printf("Password for %s has been reset to: %s\n", did.String(), newPass)
			return nil
		},
	}

	cmd.Flags().String("did", "", "DID of the user whose password to reset (required)")
	_ = cmd.MarkFlagRequired("did")

	return cmd
}
