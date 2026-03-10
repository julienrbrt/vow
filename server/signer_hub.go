package server

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ErrSignerTimeout is returned by SignerHub.RequestSignature when no signature
// arrives within the deadline.
var ErrSignerTimeout = errors.New("signer timeout: no response from signer within deadline")

// ErrSignerNotConnected is returned when no signer WebSocket is registered for
// the requested DID.
var ErrSignerNotConnected = errors.New("signer not connected: no signer is connected for this account")

// ErrSignerRejected is returned when the signer sends a sign_reject message.
var ErrSignerRejected = errors.New("signer rejected: user declined the signing request in their wallet")

// signerRequest is the internal envelope passed from RequestSignature to the
// goroutine that owns the WebSocket connection for a given DID.
type signerRequest struct {
	// requestID is a unique identifier correlating the sign_request sent over
	// the WebSocket with the sign_response or sign_reject that comes back.
	requestID string

	// msg is the sign_request JSON bytes to push to the signer.
	msg []byte

	// reply receives exactly one value: either the raw signature bytes on
	// success, or nil on rejection. The channel is always closed after one
	// send so callers can also select on it safely.
	reply chan signerReply
}

type signerReply struct {
	sig []byte // nil means rejected
	err error  // non-nil means an internal failure (e.g. connection dropped)
}

// signerConn represents one active signer WebSocket connection for a DID.
type signerConn struct {
	// requests is written to by RequestSignature and read by the WS handler
	// goroutine. Buffered at 1 so RequestSignature never blocks if the handler
	// is momentarily busy — it just falls through to the "not connected" path
	// if the channel is full (meaning a request is already in flight).
	requests chan signerRequest

	// done is closed when the WebSocket disconnects so that any in-flight
	// RequestSignature call can unblock immediately.
	done chan struct{}
}

// SignerHub manages the mapping from DID to the active signer WebSocket
// connection. It is the only piece of shared state between the WS handler
// goroutine (which owns the connection and drives reads/writes) and the
// write-request handlers (which need a signature before they can respond).
//
// Thread-safety: all exported methods are safe for concurrent use.
type SignerHub struct {
	mu    sync.Mutex
	conns map[string]*signerConn // keyed by DID
}

// NewSignerHub allocates an empty SignerHub.
func NewSignerHub() *SignerHub {
	return &SignerHub{
		conns: make(map[string]*signerConn),
	}
}

// Register records a new signer connection for did and returns the
// signerConn the WS handler should use to receive signing requests. If a
// previous connection existed for the same DID it is evicted: its done channel
// is closed so any in-flight RequestSignature unblocks with ErrSignerNotConnected,
// and the new connection takes over.
func (h *SignerHub) Register(did string) *signerConn {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Evict any existing connection for this DID.
	if old, ok := h.conns[did]; ok {
		close(old.done)
	}

	conn := &signerConn{
		// Buffered at 1: holds at most one pending request. RequestSignature
		// checks fullness before sending so it never blocks.
		requests: make(chan signerRequest, 1),
		done:     make(chan struct{}),
	}
	h.conns[did] = conn
	return conn
}

// Unregister removes the connection for did if it is still the same conn
// pointer that was registered. This avoids a race where a new connection
// registered by a concurrent call is accidentally removed.
func (h *SignerHub) Unregister(did string, conn *signerConn) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if current, ok := h.conns[did]; ok && current == conn {
		delete(h.conns, did)
		// Close done in case it hasn't been closed yet (e.g. clean shutdown
		// path where Register was not called again for the same DID).
		select {
		case <-conn.done:
			// already closed
		default:
			close(conn.done)
		}
	}
}

// IsConnected reports whether a signer is currently registered for did.
func (h *SignerHub) IsConnected(did string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	_, ok := h.conns[did]
	return ok
}

// RequestSignature sends msg (a JSON sign_request) to the signer registered
// for did and waits for a signature response, blocking until one of:
//   - The signer sends sign_response → returns the signature bytes.
//   - The signer sends sign_reject  → returns ErrSignerRejected.
//   - The signer disconnects        → returns ErrSignerNotConnected.
//   - ctx is cancelled or times out    → returns ctx.Err() (caller sets the
//     deadline, typically 30 s).
//
// requestID must match the "requestId" field embedded in msg so the WS handler
// can route the reply back correctly.
//
// Only one request per DID can be in flight at a time. If a request is already
// queued for this DID, RequestSignature returns ErrSignerNotConnected immediately
// rather than blocking or overwriting the in-flight request.
func (h *SignerHub) RequestSignature(ctx context.Context, did string, requestID string, msg []byte) ([]byte, error) {
	h.mu.Lock()
	conn, ok := h.conns[did]
	h.mu.Unlock()

	if !ok {
		return nil, ErrSignerNotConnected
	}

	reply := make(chan signerReply, 1)

	req := signerRequest{
		requestID: requestID,
		msg:       msg,
		reply:     reply,
	}

	// Non-blocking send: if the channel already holds a request the signer
	// is busy with another operation for this account.
	select {
	case conn.requests <- req:
	default:
		return nil, ErrSignerNotConnected
	}

	select {
	case r := <-reply:
		if r.err != nil {
			return nil, r.err
		}
		if r.sig == nil {
			return nil, ErrSignerRejected
		}
		return r.sig, nil

	case <-conn.done:
		// The WebSocket dropped while we were waiting.
		return nil, ErrSignerNotConnected

	case <-ctx.Done():
		if ctx.Err() == context.DeadlineExceeded {
			return nil, ErrSignerTimeout
		}
		return nil, ctx.Err()
	}
}

// DeliverSignature is called by the WS handler goroutine when a sign_response
// message arrives. It looks up the in-flight request by requestID and sends
// the signature bytes to the waiting RequestSignature call.
//
// Returns false if no matching in-flight request was found (e.g. it already
// timed out).
func (h *SignerHub) DeliverSignature(did string, requestID string, sig []byte) bool {
	return h.deliver(did, requestID, signerReply{sig: sig})
}

// DeliverRejection is called by the WS handler goroutine when a sign_reject
// message arrives.
func (h *SignerHub) DeliverRejection(did string, requestID string) bool {
	return h.deliver(did, requestID, signerReply{sig: nil})
}

// deliver routes a reply to the waiting RequestSignature call identified by
// requestID. Because the reply channel is buffered at 1 this never blocks.
func (h *SignerHub) deliver(did string, requestID string, reply signerReply) bool {
	h.mu.Lock()
	conn, ok := h.conns[did]
	h.mu.Unlock()

	if !ok {
		return false
	}

	// Peek at the request currently sitting in the queue. We cannot remove it
	// here (only the WS handler goroutine drains the channel), but we can
	// inspect the requestID by doing a non-blocking receive and then putting
	// it back. This is safe because DeliverSignature / DeliverRejection are
	// only ever called from the single WS handler goroutine that also drains
	// conn.requests, so there is no concurrent drain racing us.
	select {
	case req := <-conn.requests:
		if req.requestID != requestID {
			// Wrong request — put it back and report not found.
			conn.requests <- req
			return false
		}
		// Correct request: send the reply. The channel is buffered at 1 so
		// this is non-blocking.
		req.reply <- reply
		return true
	default:
		return false
	}
}

// NextRequest returns the next signing request for conn, blocking until one
// arrives, the connection's done channel is closed, or ctx is cancelled.
// Returns (request, true) on success or (zero, false) if the connection is
// going away.
func (conn *signerConn) NextRequest(ctx context.Context) (signerRequest, bool) {
	select {
	case req := <-conn.requests:
		return req, true
	case <-conn.done:
		return signerRequest{}, false
	case <-ctx.Done():
		return signerRequest{}, false
	}
}

// signerRequestTimeout is the maximum time RequestSignature will wait for a
// signature before returning ErrSignerTimeout. It is also the deadline used
// when building the sign_request message's expiresAt field.
const signerRequestTimeout = 30 * time.Second
