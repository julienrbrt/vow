package server

import (
	"context"
	"sync"
	"time"

	"pkg.rbrt.fr/vow/internal/helpers"
)

// signerRequest is the internal envelope passed from RequestSignature to the
// goroutine that owns the WebSocket connection for a given DID.
type signerRequest struct {
	// requestID is a unique identifier correlating the sign_request sent over
	// the WebSocket with the sign_response or sign_reject that comes back.
	requestID string

	// msg is the sign_request JSON bytes to push to the signer.
	msg []byte

	// reply receives exactly one value: either the raw signature bytes on
	// success, or an error. The channel is buffered at 1 so the WS goroutine
	// never blocks delivering the result.
	reply chan signerReply
}

type signerReply struct {
	sig []byte // nil means rejected
	err error  // non-nil means an internal failure (e.g. connection dropped)
}

// signerConn represents one active signer WebSocket connection for a DID.
// It owns an unbounded queue of pending requests and a map of in-flight
// requests waiting for a reply from the wallet.
type signerConn struct {
	// mu protects pending and inflight.
	mu sync.Mutex

	// pending is an ordered queue of requests that have not yet been sent to
	// the wallet. The WS goroutine drains it one at a time: it pops the head,
	// sends the sign_request frame, moves the request into inflight, and only
	// pops the next one after a reply arrives. This serialises wallet prompts
	// (the user must confirm each one before the next appears) while allowing
	// any number of callers to enqueue work concurrently.
	pending []signerRequest

	// inflight holds the single request that has been sent to the wallet and
	// is awaiting a sign_response / sign_reject. Keyed by requestID.
	inflight map[string]signerRequest

	// notify is used to wake the WS goroutine when a new request is enqueued.
	// Buffered at 1: if the goroutine is already awake the send is a no-op.
	notify chan struct{}

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

func newSignerConn() *signerConn {
	return &signerConn{
		inflight: make(map[string]signerRequest),
		notify:   make(chan struct{}, 1),
		done:     make(chan struct{}),
	}
}

// Register records a new signer connection for did and returns the signerConn
// the WS handler should use. If a previous connection existed for the same DID
// it is evicted: its done channel is closed so any waiting RequestSignature
// calls unblock with helpers.ErrSignerNotConnected, and the new connection takes over.
func (h *SignerHub) Register(did string) *signerConn {
	h.mu.Lock()
	defer h.mu.Unlock()

	if old, ok := h.conns[did]; ok {
		close(old.done)
	}

	conn := newSignerConn()
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

// RequestSignature enqueues a signing request for did and blocks until one of:
//   - The wallet sends sign_response  → returns the signature bytes.
//   - The wallet sends sign_reject    → returns helpers.ErrSignerRejected.
//   - The WebSocket disconnects       → returns helpers.ErrSignerNotConnected.
//   - ctx is cancelled or times out  → returns helpers.ErrSignerTimeout or ctx.Err().
//
// Multiple callers for the same DID are all queued and processed sequentially
// (the wallet sees one prompt at a time). Callers for different DIDs are
// independent.
func (h *SignerHub) RequestSignature(ctx context.Context, did string, requestID string, msg []byte) ([]byte, error) {
	h.mu.Lock()
	conn, ok := h.conns[did]
	h.mu.Unlock()

	if !ok {
		return nil, helpers.ErrSignerNotConnected
	}

	reply := make(chan signerReply, 1)

	req := signerRequest{
		requestID: requestID,
		msg:       msg,
		reply:     reply,
	}

	// Enqueue and wake the WS goroutine.
	conn.mu.Lock()
	conn.pending = append(conn.pending, req)
	conn.mu.Unlock()

	select {
	case conn.notify <- struct{}{}:
	default:
		// WS goroutine already has a pending notification.
	}

	// Wait for the reply, connection drop, or context cancellation.
	select {
	case r := <-reply:
		if r.err != nil {
			return nil, r.err
		}
		if r.sig == nil {
			return nil, helpers.ErrSignerRejected
		}
		return r.sig, nil

	case <-conn.done:
		return nil, helpers.ErrSignerNotConnected

	case <-ctx.Done():
		// Remove from pending queue if not yet sent, so the WS goroutine
		// doesn't try to send a request nobody is waiting for.
		conn.mu.Lock()
		for i, p := range conn.pending {
			if p.requestID == requestID {
				conn.pending = append(conn.pending[:i], conn.pending[i+1:]...)
				break
			}
		}
		conn.mu.Unlock()

		if ctx.Err() == context.DeadlineExceeded {
			return nil, helpers.ErrSignerTimeout
		}
		return nil, ctx.Err()
	}
}

// DeliverSignature is called by the WS handler goroutine when a sign_response
// arrives. It routes the signature to the waiting RequestSignature call.
//
// Returns false if no matching in-flight request was found (e.g. it already
// timed out).
func (h *SignerHub) DeliverSignature(did string, requestID string, sig []byte) bool {
	return h.deliver(did, requestID, signerReply{sig: sig})
}

// DeliverRejection is called by the WS handler goroutine when a sign_reject
// arrives.
func (h *SignerHub) DeliverRejection(did string, requestID string) bool {
	return h.deliver(did, requestID, signerReply{sig: nil})
}

func (h *SignerHub) deliver(did string, requestID string, reply signerReply) bool {
	h.mu.Lock()
	conn, ok := h.conns[did]
	h.mu.Unlock()

	if !ok {
		return false
	}

	conn.mu.Lock()
	req, found := conn.inflight[requestID]
	if found {
		delete(conn.inflight, requestID)
	}
	conn.mu.Unlock()

	if !found {
		return false
	}

	req.reply <- reply

	// A slot freed up — wake the WS goroutine so it can send the next pending
	// request.
	select {
	case conn.notify <- struct{}{}:
	default:
	}

	return true
}

// NextRequest blocks until a pending request is ready to be sent to the wallet
// and no other request is currently in-flight (wallets handle one prompt at a
// time). It moves the request from pending into inflight before returning, so
// the caller just needs to write it to the WebSocket.
//
// Returns (request, true) on success, or (zero, false) if the connection is
// going away (done closed or ctx cancelled).
func (conn *signerConn) NextRequest(ctx context.Context) (signerRequest, bool) {
	for {
		conn.mu.Lock()
		// Only dequeue when nothing is in-flight (wallet is free).
		if len(conn.pending) > 0 && len(conn.inflight) == 0 {
			req := conn.pending[0]
			conn.pending = conn.pending[1:]
			conn.inflight[req.requestID] = req
			conn.mu.Unlock()
			return req, true
		}
		conn.mu.Unlock()

		// Wait for either a new enqueue notification or the connection going away.
		select {
		case <-conn.notify:
			// Loop and re-check.
		case <-conn.done:
			return signerRequest{}, false
		case <-ctx.Done():
			return signerRequest{}, false
		}
	}
}

// failAll unblocks all waiting RequestSignature callers with err. Called by
// the WS goroutine on disconnect to drain both inflight and pending queues so
// no goroutine leaks.
func (conn *signerConn) failAll(err error) {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	reply := signerReply{err: err}

	for _, req := range conn.inflight {
		req.reply <- reply
	}
	conn.inflight = make(map[string]signerRequest)

	for _, req := range conn.pending {
		req.reply <- reply
	}
	conn.pending = nil
}

// signerRequestTimeout is the maximum time RequestSignature will wait for a
// signature before returning helpers.ErrSignerTimeout. It is also the deadline used
// when building the sign_request message's expiresAt field.
const signerRequestTimeout = 30 * time.Second
