package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/gorilla/websocket"
	"pkg.rbrt.fr/vow/internal/helpers"
	"pkg.rbrt.fr/vow/models"
)

var wsUpgrader = websocket.Upgrader{
	HandshakeTimeout: 10 * time.Second,
	CheckOrigin: func(r *http.Request) bool {
		// Origin validation is handled by the access-token check that runs
		// before the upgrade. We accept any origin here so programmatic
		// clients can connect regardless of their origin.
		return true
	},
}

// wsCloseTokenExpired is the WebSocket application close code the server sends
// when it detects that the access token used to authenticate the signer
// connection has expired mid-session. The client listens for this code and
// triggers an immediate token refresh + reconnect rather than doing a back-off
// retry.
const wsCloseTokenExpired = 4001

// wsSignRequest is the JSON envelope pushed to the signer for every write
// operation that needs a user signature.
type wsSignRequest struct {
	Type      string           `json:"type"`      // always "sign_request"
	RequestID string           `json:"requestId"` // UUID, echoed back in the response
	Did       string           `json:"did"`
	Payload   string           `json:"payload"`   // base64url-encoded unsigned commit CBOR (used as the WebAuthn challenge)
	Ops       []PendingWriteOp `json:"ops"`       // human-readable summary shown to user
	ExpiresAt string           `json:"expiresAt"` // RFC3339
}

// wsIncoming is used for initial type-sniffing before full decode.
//
// sign_response carries the three fields from the WebAuthn AuthenticatorAssertionResponse:
//   - AuthenticatorData: base64url authenticatorData bytes
//   - ClientDataJSON:    base64url clientDataJSON bytes
//   - Signature:         base64url DER-encoded ECDSA signature
type wsIncoming struct {
	Type              string `json:"type"`
	RequestID         string `json:"requestId"`
	AuthenticatorData string `json:"authenticatorData,omitempty"` // base64url
	ClientDataJSON    string `json:"clientDataJSON,omitempty"`    // base64url
	Signature         string `json:"signature,omitempty"`         // base64url DER-encoded ECDSA
	CommitSignature   string `json:"commitSignature,omitempty"`   // base64url 64-byte raw r||s signature
}

// handleSignerConnect upgrades the connection to a WebSocket and registers it
// in the SignerHub. This is the Bearer-token-authenticated endpoint used by
// programmatic clients. The browser-based signer uses handleAccountSigner
// (cookie-authenticated) instead.
//
// From that point on the PDS drives the conversation:
//
//  1. When a write handler needs a signature it calls SignerHub.RequestSignature
//     which pushes a signerRequest onto the conn.requests channel.
//  2. This goroutine picks it up, writes the sign_request JSON frame, and waits
//     for a sign_response or sign_reject from the client.
//  3. The WebAuthn assertion is verified here; the resulting raw (r‖s) signature
//     bytes are forwarded to the waiting write handler via DeliverSignature.
//
// The loop also handles WebSocket ping/pong: the server sends a ping every 20 s
// and expects a pong within 10 s (gorilla handles pong automatically).
//
// Token expiry: if the access token used to open this connection expires while
// the connection is alive, the server sends a close frame with code 4001. The
// client handles this by refreshing the token immediately and reconnecting.
func (s *Server) handleSignerConnect(w http.ResponseWriter, r *http.Request) {
	logger := s.logger.With("name", "handleSignerConnect")

	// The middleware has already validated the access token and set contextKeyRepo.
	repo, ok := getContextValue[*models.RepoActor](r, contextKeyRepo)
	if !ok {
		helpers.UnauthorizedError(w, nil)
		return
	}
	did := repo.Repo.Did

	// Ensure the account actually has a public key registered before accepting
	// a signer connection; without it no signature can ever be verified.
	if len(repo.AuthPublicKey) == 0 {
		helpers.InputError(w, new("no signing key registered for this account"))
		return
	}

	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		// Upgrade writes its own error response on failure.
		logger.Error("ws upgrade failed", "did", did, "error", err)
		return
	}
	defer func() { _ = conn.Close() }()

	logger.Info("signer connected (bearer)", "did", did)

	// Register this connection with the hub, evicting any previous connection
	// for the same DID.
	sc := s.signerHub.Register(did)
	defer func() {
		s.signerHub.Unregister(did, sc)
		sc.failAll(helpers.ErrSignerNotConnected)
	}()

	// Configure the pong deadline handler: whenever a pong arrives we extend
	// the read deadline by another 30 s.
	if err := conn.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		logger.Error("signer: failed to set initial read deadline", "did", did, "error", err)
		return
	}
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	})

	// pingTicker drives the server-side keep-alive. We send a ping every 20 s.
	pingTicker := time.NewTicker(20 * time.Second)
	defer pingTicker.Stop()

	// tokenTicker checks whether the session token is still valid every minute.
	// If it has expired we close with code 4001 so the client can refresh
	// and reconnect immediately rather than waiting for a back-off retry.
	tokenTicker := time.NewTicker(1 * time.Minute)
	defer tokenTicker.Stop()

	// Retrieve the raw token string that was used to open this connection so we
	// can check its expiry claim periodically.
	sessionToken, _ := getContextValue[string](r, contextKeyToken)

	// readErr carries any error from the dedicated reader goroutine.
	readErr := make(chan error, 1)

	// inbound carries decoded messages from the reader goroutine.
	inbound := make(chan wsIncoming, 4)

	// nextReq carries the next queued request to be sent to the signer.
	nextReq := make(chan signerRequest, 1)

	// pendingPayloads maps requestID → base64url payload so that when a
	// sign_response arrives we can reconstruct the expected WebAuthn challenge
	// (the raw bytes that the payload string encodes).
	pendingPayloads := make(map[string]string)

	ctx := r.Context()

	// Read pump: conn.ReadMessage blocks so it runs in its own goroutine.
	go func() {
		for {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				readErr <- err
				return
			}
			var in wsIncoming
			if err := json.Unmarshal(msg, &in); err != nil {
				logger.Warn("signer: unreadable message", "did", did, "error", err)
				continue
			}
			select {
			case inbound <- in:
			case <-ctx.Done():
				return
			}
		}
	}()

	// Queue pump: feeds the main loop one request at a time, respecting the
	// passkey's one-at-a-time constraint enforced inside NextRequest.
	go func() {
		for {
			req, ok := sc.NextRequest(ctx)
			if !ok {
				return
			}
			select {
			case nextReq <- req:
			case <-ctx.Done():
				return
			case <-sc.done:
				return
			}
		}
	}()

	for {
		select {
		// ── keep-alive ping ──────────────────────────────────────────────
		case <-pingTicker.C:
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				logger.Warn("signer: ping failed", "did", did, "error", err)
				return
			}

		// ── periodic token expiry check ───────────────────────────────────
		case <-tokenTicker.C:
			if sessionToken != "" && isTokenExpired(sessionToken) {
				logger.Info("signer: session token expired — closing with 4001", "did", did)
				_ = conn.WriteControl(
					websocket.CloseMessage,
					websocket.FormatCloseMessage(wsCloseTokenExpired, "token expired"),
					time.Now().Add(5*time.Second),
				)
				return
			}

		// ── incoming message from signer ─────────────────────────────────
		case in := <-inbound:
			switch in.Type {
			case "sign_response":
				payload, ok := pendingPayloads[in.RequestID]
				if !ok {
					logger.Warn("signer: sign_response for unknown requestId (no payload)", "did", did, "requestId", in.RequestID)
					continue
				}
				delete(pendingPayloads, in.RequestID)

				rawSig, err := verifyWebAuthnSignResponse(repo.AuthPublicKey, repo.SigningPublicKey, payload, in, s.config.Hostname, logger)
				if err != nil {
					logger.Warn("signer: sign_response verification failed", "did", did, "requestId", in.RequestID, "error", err)
					continue
				}
				if !s.signerHub.DeliverSignature(did, in.RequestID, rawSig) {
					logger.Warn("signer: sign_response for unknown requestId", "did", did, "requestId", in.RequestID)
				}

			case "sign_reject":
				delete(pendingPayloads, in.RequestID)
				if !s.signerHub.DeliverRejection(did, in.RequestID) {
					logger.Warn("signer: sign_reject for unknown requestId", "did", did, "requestId", in.RequestID)
				}

			default:
				logger.Warn("signer: unknown message type", "did", did, "type", in.Type)
			}

		// ── next queued signing request ready to send ─────────────────────
		case req := <-nextReq:
			if err := conn.WriteMessage(websocket.TextMessage, req.msg); err != nil {
				logger.Error("signer: failed to write request", "did", did, "error", err)
				req.reply <- signerReply{err: helpers.ErrSignerNotConnected}
				return
			}

			// Record the payload so we can verify the WebAuthn challenge when
			// the sign_response arrives.
			if payload, err := extractPayloadFromMsg(req.msg); err == nil {
				pendingPayloads[req.requestID] = payload
			} else {
				logger.Warn("signer: could not extract payload from sign_request", "did", did, "error", err)
			}

			logger.Info("signer: request sent", "did", did, "requestId", req.requestID)

		// ── read pump died ────────────────────────────────────────────────
		case err := <-readErr:
			if websocket.IsUnexpectedCloseError(err,
				websocket.CloseGoingAway,
				websocket.CloseNormalClosure,
			) {
				logger.Warn("signer: connection closed unexpectedly", "did", did, "error", err)
			} else {
				logger.Info("signer: disconnected", "did", did)
			}
			return

		// ── request context cancelled (server shutdown etc.) ──────────────
		case <-ctx.Done():
			return
		}
	}
}

// buildSignRequestMsg constructs the JSON bytes for a sign_request WebSocket
// message. It is called by applyWrites (and the PLC signing path) before
// handing the request off to SignerHub.RequestSignature.
func buildSignRequestMsg(requestID string, did string, payloadB64 string, ops []PendingWriteOp, expiresAt time.Time) ([]byte, error) {
	return json.Marshal(wsSignRequest{
		Type:      "sign_request",
		RequestID: requestID,
		Did:       did,
		Payload:   payloadB64,
		Ops:       ops,
		ExpiresAt: expiresAt.UTC().Format(time.RFC3339),
	})
}

// extractPayloadFromMsg extracts the "payload" field from a sign_request JSON
// message without a full re-parse.
func extractPayloadFromMsg(msg []byte) (string, error) {
	var req struct {
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(msg, &req); err != nil {
		return "", err
	}
	if req.Payload == "" {
		return "", nil
	}
	return req.Payload, nil
}

// verifyWebAuthnSignResponse decodes the three base64url fields from a
// sign_response message, reconstructs the expected challenge from the payload,
// verifies the WebAuthn P-256 assertion, and returns the raw 64-byte (r‖s)
// signature for use in ATProto commits and JWTs.
//
// pubKey is the compressed P-256 public key stored in the database.
// payloadB64 is the base64url-encoded challenge bytes that were sent in the
// sign_request (the raw CBOR bytes of the unsigned commit, or the SHA-256 of
// the JWT signing input for service-auth tokens).
func verifyWebAuthnSignResponse(
	authPubKey []byte,
	signingPubKey []byte,
	payloadB64 string,
	in wsIncoming,
	rpID string,
	logger *slog.Logger,
) ([]byte, error) {
	if in.AuthenticatorData == "" || in.ClientDataJSON == "" || in.Signature == "" {
		return nil, helpers.ErrSignerNotConnected // reuse a sentinel; caller logs
	}

	if in.CommitSignature == "" {
		return nil, fmt.Errorf("missing commitSignature in sign_response")
	}

	// The challenge passed to navigator.credentials.get() was the raw bytes
	// decoded from payloadB64. The browser re-encodes them as base64url in
	// clientDataJSON.challenge — so the expected challenge is exactly those
	// raw bytes.
	expectedChallenge, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, err
	}

	clientDataJSONBytes, err := base64.RawURLEncoding.DecodeString(in.ClientDataJSON)
	if err != nil {
		return nil, err
	}

	authenticatorDataBytes, err := base64.RawURLEncoding.DecodeString(in.AuthenticatorData)
	if err != nil {
		return nil, err
	}

	signatureDER, err := base64.RawURLEncoding.DecodeString(in.Signature)
	if err != nil {
		return nil, err
	}

	_, err = verifyAssertion(authPubKey, expectedChallenge, clientDataJSONBytes, authenticatorDataBytes, signatureDER, rpID)
	if err != nil {
		logger.With("rpID", rpID).Debug("verifyAssertion detail", "error", err)
		return nil, err
	}

	commitSig, err := base64.RawURLEncoding.DecodeString(in.CommitSignature)
	if err != nil {
		return nil, fmt.Errorf("invalid commitSignature encoding: %w", err)
	}

	if len(commitSig) != 64 {
		return nil, fmt.Errorf("invalid commitSignature length: got %d, want 64", len(commitSig))
	}

	// Verify the commit signature against the registered signing key.
	pubKey, err := atcrypto.ParsePublicBytesP256(signingPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse registered signing key: %w", err)
	}

	if err := pubKey.HashAndVerifyLenient(expectedChallenge, commitSig); err != nil {
		return nil, fmt.Errorf("commit signature verification failed: %w", err)
	}

	return commitSig, nil
}

// isTokenExpired returns true if the JWT's exp claim is in the past.
// It performs no signature verification — the token was already verified when
// the WebSocket connection was established. This is purely a liveness check.
func isTokenExpired(tokenStr string) bool {
	// A JWT is three base64url segments separated by dots.
	parts := strings.SplitN(tokenStr, ".", 3)
	if len(parts) != 3 {
		return true
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return true
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return true
	}
	return claims.Exp > 0 && time.Now().Unix() > claims.Exp
}
