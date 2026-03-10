package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	x402 "github.com/coinbase/x402/go"
	x402http "github.com/coinbase/x402/go/http"
	x402evm "github.com/coinbase/x402/go/mechanisms/evm"
	evmexactclient "github.com/coinbase/x402/go/mechanisms/evm/exact/client"
	"github.com/google/uuid"
)

// readJSON decodes a single JSON value from r into dst.
func readJSON(r io.Reader, dst any) error {
	return json.NewDecoder(r).Decode(dst)
}

// ── signerHubEvmSigner ────────────────────────────────────────────────────────

// signerHubEvmSigner implements x402evm.ClientEvmSigner by delegating
// SignTypedData to the user's Ethereum wallet via the signer WebSocket.
// This means the PDS never holds a private key — the EIP-712 payload is
// forwarded to the signer as a pay_request message and the resulting
// 65-byte signature is returned through the SignerHub.
type signerHubEvmSigner struct {
	hub     *SignerHub
	did     string
	address string // EIP-55 checksummed Ethereum address
}

// Address returns the EIP-55 checksummed Ethereum address of the signer,
// derived from the account's stored secp256k1 public key.
func (s *signerHubEvmSigner) Address() string {
	return s.address
}

// SignTypedData sends the EIP-712 typed data to the signer as a pay_request
// WebSocket message and blocks until the signer returns the 65-byte signature
// via pay_response, or until the context is cancelled.
//
// The typed data is serialised to JSON and forwarded verbatim so the signer
// can pass it directly to eth_signTypedData_v4 without any transformation.
func (s *signerHubEvmSigner) SignTypedData(
	ctx context.Context,
	domain x402evm.TypedDataDomain,
	types map[string][]x402evm.TypedDataField,
	primaryType string,
	message map[string]any,
) ([]byte, error) {
	// Serialise the full EIP-712 object so the signer can call
	// eth_signTypedData_v4(walletAddress, JSON.stringify(typedData)).
	typedDataPayload := map[string]any{
		"domain":      domain,
		"types":       types,
		"primaryType": primaryType,
		"message":     message,
	}
	typedDataJSON, err := json.Marshal(typedDataPayload)
	if err != nil {
		return nil, fmt.Errorf("x402: marshalling typed data: %w", err)
	}

	requestID := uuid.NewString()
	expiresAt := time.Now().Add(signerRequestTimeout)

	// Build a human-readable description from the typed data message fields
	// so the signer can show it in the notification before prompting.
	description := buildPayDescription(domain, message)

	msg, err := json.Marshal(wsPayRequest{
		Type:          "pay_request",
		RequestID:     requestID,
		Did:           s.did,
		TypedData:     typedDataJSON,
		WalletAddress: s.address,
		Description:   description,
		ExpiresAt:     expiresAt.UTC().Format(time.RFC3339),
	})
	if err != nil {
		return nil, fmt.Errorf("x402: encoding pay_request: %w", err)
	}

	signCtx, cancel := context.WithDeadline(ctx, expiresAt)
	defer cancel()

	// RequestSignature blocks until the signer returns the signature bytes
	// (delivered via pay_response) or the context times out / user rejects.
	return s.hub.RequestSignature(signCtx, s.did, requestID, msg)
}

// ReadContract is not implemented — the PDS has no RPC connection and the
// x402 EIP-3009 flow does not require on-chain reads on the client side.
func (s *signerHubEvmSigner) ReadContract(
	_ context.Context,
	_ string,
	_ []byte,
	_ string,
	_ ...any,
) (any, error) {
	return nil, fmt.Errorf("x402: ReadContract not supported on keyless PDS")
}

// ── wsPayRequest ──────────────────────────────────────────────────────────────

// wsPayRequest is the WebSocket message the PDS sends to the signer when it
// needs the user's wallet to sign an EIP-712 typed-data payload for an x402
// EIP-3009 payment authorisation.
type wsPayRequest struct {
	Type string `json:"type"` // always "pay_request"
	// RequestID is a UUID echoed back in the pay_response so the SignerHub
	// can route the reply to the correct waiting goroutine.
	RequestID string `json:"requestId"`
	Did       string `json:"did"`
	// TypedData is the full EIP-712 object (domain, types, primaryType,
	// message) as produced by the x402 SDK. The signer passes it verbatim
	// to eth_signTypedData_v4(walletAddress, JSON.stringify(typedData)).
	TypedData json.RawMessage `json:"typedData"`
	// WalletAddress is the EIP-55 checksummed Ethereum address of the payer,
	// derived from the account's stored public key. Passed to the wallet as
	// the first argument of eth_signTypedData_v4.
	WalletAddress string `json:"walletAddress"`
	// Description is a human-readable summary shown in the signer's
	// notification before the wallet prompt appears, e.g.
	// "Pin blob bafyrei… (12 KB) via x402 on eip155:8453".
	Description string `json:"description,omitempty"`
	ExpiresAt   string `json:"expiresAt"` // RFC3339
}

// ── x402 HTTP client factory ──────────────────────────────────────────────────

// newX402HTTPClient builds an *http.Client that transparently handles the x402
// 402-payment handshake for the given account. On a 402 response it:
//
//  1. Parses the payment requirements using the x402 SDK.
//  2. Calls signerHubEvmSigner.SignTypedData, which sends a pay_request over
//     the account's signer WebSocket and waits for the wallet signature.
//  3. Encodes the signed PaymentPayload and retries the original request with
//     the X-PAYMENT / PAYMENT-SIGNATURE header set.
func (s *Server) newX402HTTPClient(did, walletAddress string) *http.Client {
	signer := &signerHubEvmSigner{
		hub:     s.signerHub,
		did:     did,
		address: walletAddress,
	}

	x402Client := x402.Newx402Client().
		Register(
			x402.Network(s.ipfsConfig.X402.Network),
			evmexactclient.NewExactEvmScheme(signer),
		)

	return x402http.WrapHTTPClientWithPayment(
		&http.Client{Timeout: 2 * signerRequestTimeout},
		x402http.Newx402HTTPClient(x402Client),
	)
}

// ── request / response types ──────────────────────────────────────────────────

// x402PinRequest is the JSON body posted to the x402 pinning endpoint.
// Pinata's server requires the file size upfront so it can compute a dynamic
// price before the file is transferred.
type x402PinRequest struct {
	FileSize int `json:"fileSize"`
}

// x402PinResponse is the success body returned by the pinning endpoint.
// Pinata returns a presigned upload URL the caller can use to push content
// directly without an API key.
type x402PinResponse struct {
	URL string `json:"url"`
}

// ── pinBlobWithX402 ───────────────────────────────────────────────────────────

// pinBlobWithX402 pins cidStr to the configured x402 pinning endpoint on
// behalf of the account identified by did / walletAddress. The end-to-end flow:
//
//  1. POST the file size to cfg.PinURL.
//  2. The x402 HTTP transport intercepts the 402 response, selects a payment
//     requirement, and calls signerHubEvmSigner.SignTypedData.
//  3. SignTypedData sends a pay_request WebSocket message to the signer and
//     blocks until the wallet returns the EIP-712 signature.
//  4. The transport re-encodes the signed PaymentPayload and retries the POST
//     with the appropriate payment header.
//  5. On success the presigned URL (if returned) is logged.
//
// The call is intentionally non-fatal: the blob is already safe on the local
// Kubo node. Callers should log any returned error but not propagate it as an
// ATProto failure.
func (s *Server) pinBlobWithX402(ctx context.Context, did, walletAddress, cidStr string, fileSize int) error {
	cfg := s.ipfsConfig.X402
	if cfg == nil || cfg.PinURL == "" {
		return fmt.Errorf("x402 pinning not configured")
	}

	logger := s.logger.With("op", "x402Pin", "did", did, "cid", cidStr)

	body, err := json.Marshal(x402PinRequest{FileSize: fileSize})
	if err != nil {
		return fmt.Errorf("x402: encoding pin request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.PinURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("x402: building pin request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	// Provide GetBody so the x402 transport can replay the body on the
	// payment-retry request without consuming the original reader twice.
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}

	httpClient := s.newX402HTTPClient(did, walletAddress)

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("x402: pin request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		msg, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("x402: pin rejected (status %d): %s", resp.StatusCode, string(msg))
	}

	var pinResp x402PinResponse
	if err := readJSON(resp.Body, &pinResp); err == nil && pinResp.URL != "" {
		logger.Info("x402 pin accepted", "presignedURL", pinResp.URL)
	} else {
		logger.Info("x402 pin accepted")
	}

	return nil
}

// ── unpinFromIPFS ─────────────────────────────────────────────────────────────

// unpinFromIPFS asks the local Kubo node to remove the recursive pin for the
// given CID so the content becomes eligible for garbage collection.
// It is intentionally best-effort: errors are logged but not propagated.
func (s *Server) unpinFromIPFS(cidStr string) {
	endpoint := s.ipfsConfig.NodeURL + "/api/v0/pin/rm?arg=" + cidStr + "&recursive=true"

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, endpoint, nil)
	if err != nil {
		s.logger.Warn("ipfs unpin: failed to build request", "cid", cidStr, "error", err)
		return
	}

	resp, err := s.http.Do(req)
	if err != nil {
		s.logger.Warn("ipfs unpin: request failed", "cid", cidStr, "error", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	// Kubo returns 500 with "not pinned" in the body if the CID was never
	// pinned — treat that as a no-op rather than an error worth logging loudly.
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(resp.Body)
		s.logger.Warn("ipfs unpin: unexpected status",
			"cid", cidStr,
			"status", resp.StatusCode,
			"body", string(msg),
		)
		return
	}

	s.logger.Info("ipfs unpin: blob unpinned", "cid", cidStr)
}

// ── compile-time interface assertions ─────────────────────────────────────────

// Ensure signerHubEvmSigner satisfies the x402 ClientEvmSigner interface so
// that build failures surface here rather than deep in the x402 SDK internals.
var _ x402evm.ClientEvmSigner = (*signerHubEvmSigner)(nil)

// buildPayDescription creates a short human-readable description of the
// payment for use in the signer notification. It extracts the token value
// and recipient from the EIP-712 message fields, falling back to a generic
// string if the fields are missing or unparseable.
func buildPayDescription(domain x402evm.TypedDataDomain, message map[string]any) string {
	value, _ := message["value"].(string)
	to, _ := message["to"].(string)

	chainID := ""
	if domain.ChainID != nil {
		chainID = fmt.Sprintf("eip155:%s", domain.ChainID.String())
	}

	if value != "" && to != "" && chainID != "" {
		// Truncate the recipient address for display.
		toShort := to
		if len(to) > 10 {
			toShort = to[:6] + "…" + to[len(to)-4:]
		}
		return fmt.Sprintf("x402 payment: %s units → %s on %s", value, toShort, chainID)
	}
	if value != "" && chainID != "" {
		return fmt.Sprintf("x402 payment: %s units on %s", value, chainID)
	}
	return "Authorise an x402 payment?"
}
