package server

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"pkg.rbrt.fr/vow/internal/helpers"
)

// handleAccountSigner upgrades an account session to a signer WebSocket.
func (s *Server) handleAccountSigner(w http.ResponseWriter, r *http.Request) {
	logger := s.logger.With("name", "handleAccountSigner")

	// Authenticate the session.
	repo, _, err := s.getSessionRepoOrErr(r)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	did := repo.Repo.Did

	// Require a public key.
	if len(repo.PublicKey) == 0 {
		http.Error(w, "no signing key registered for this account", http.StatusBadRequest)
		return
	}

	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		logger.Error("ws upgrade failed", "did", did, "error", err)
		return
	}
	defer func() { _ = conn.Close() }()

	logger.Info("browser signer connected", "did", did)

	// Replace any existing signer connection for this DID.
	sc := s.signerHub.Register(did)
	defer func() {
		s.signerHub.Unregister(did, sc)
		sc.failAll(helpers.ErrSignerNotConnected)
	}()

	// Keep the connection alive.
	if err := conn.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		logger.Error("signer: failed to set initial read deadline", "did", did, "error", err)
		return
	}
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	})

	pingTicker := time.NewTicker(20 * time.Second)
	defer pingTicker.Stop()

	// Session validity was checked during upgrade.

	readErr := make(chan error, 1)
	inbound := make(chan wsIncoming, 4)
	nextReq := make(chan signerRequest, 1)

	ctx := r.Context()
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
		case <-pingTicker.C:
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				logger.Warn("signer: ping failed", "did", did, "error", err)
				return
			}

		case in := <-inbound:
			switch in.Type {
			case "sign_response":
				if in.Signature == "" {
					logger.Warn("signer: sign_response missing signature", "did", did)
					continue
				}
				sigBytes, err := base64.RawURLEncoding.DecodeString(in.Signature)
				if err != nil {
					logger.Warn("signer: sign_response bad base64url", "did", did, "error", err)
					continue
				}
				if !s.signerHub.DeliverSignature(did, in.RequestID, sigBytes) {
					logger.Warn("signer: sign_response for unknown requestId", "did", did, "requestId", in.RequestID)
				}

			case "sign_reject":
				if !s.signerHub.DeliverRejection(did, in.RequestID) {
					logger.Warn("signer: sign_reject for unknown requestId", "did", did, "requestId", in.RequestID)
				}

			case "pay_response":
				if in.Signature == "" {
					logger.Warn("signer: pay_response missing signature", "did", did)
					continue
				}
				hexStr := strings.TrimPrefix(in.Signature, "0x")
				sigBytes, err := hex.DecodeString(hexStr)
				if err != nil {
					logger.Warn("signer: pay_response bad hex", "did", did, "error", err)
					continue
				}
				if !s.signerHub.DeliverSignature(did, in.RequestID, sigBytes) {
					logger.Warn("signer: pay_response for unknown requestId", "did", did, "requestId", in.RequestID)
				}

			case "pay_reject":
				if !s.signerHub.DeliverRejection(did, in.RequestID) {
					logger.Warn("signer: pay_reject for unknown requestId", "did", did, "requestId", in.RequestID)
				}

			default:
				logger.Warn("signer: unknown message type", "did", did, "type", in.Type)
			}

		case req := <-nextReq:
			if err := conn.WriteMessage(websocket.TextMessage, req.msg); err != nil {
				logger.Error("signer: failed to write request", "did", did, "error", err)
				req.reply <- signerReply{err: helpers.ErrSignerNotConnected}
				return
			}

			logger.Info("signer: request sent", "did", did, "requestId", req.requestID)

		case err := <-readErr:
			if websocket.IsUnexpectedCloseError(err,
				websocket.CloseGoingAway,
				websocket.CloseNormalClosure,
			) {
				logger.Warn("signer: connection closed unexpectedly", "did", did, "error", err)
			} else {
				logger.Info("signer: browser signer disconnected", "did", did)
			}
			return

		case <-ctx.Done():
			return
		}
	}
}
