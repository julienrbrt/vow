package server

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/bluesky-social/indigo/events"
	"github.com/bluesky-social/indigo/lex/util"
	"github.com/btcsuite/websocket"
	"pkg.rbrt.fr/vow/metrics"
)

func (s *Server) handleSyncSubscribeRepos(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	logger := s.logger.With("component", "subscribe-repos-websocket")

	conn, err := websocket.Upgrade(w, r, w.Header(), 1<<10, 1<<10)
	if err != nil {
		logger.Error("unable to establish websocket with relay", "err", err)
		return
	}

	ident := r.RemoteAddr + "-" + r.UserAgent()
	logger = logger.With("ident", ident)
	logger.Info("new connection established")

	var since *int64
	if cursorStr := r.URL.Query().Get("cursor"); cursorStr != "" {
		cursor, err := strconv.ParseInt(cursorStr, 10, 64)
		if err != nil {
			logger.Warn("invalid cursor parameter", "cursor", cursorStr, "err", err)
		} else {
			since = &cursor
			logger.Info("subscribing with cursor", "cursor", cursor)
		}
	}

	metrics.RelaysConnected.WithLabelValues(ident).Inc()
	defer func() {
		metrics.RelaysConnected.WithLabelValues(ident).Dec()
	}()

	evts, evtManCancel, err := s.evtman.Subscribe(ctx, ident, func(evt *events.XRPCStreamEvent) bool {
		return true
	}, since)
	if err != nil {
		logger.Error("error subscribing to event manager", "err", err)
		return
	}
	defer evtManCancel()

	// drop the connection whenever a subscriber disconnects from the socket, we should get errors
	go func() {
		defer cancel()

		for {
			// Use a long deadline to allow idle firehose connections without false timeouts.
			// 5 minutes is reasonable - if client disconnects, TCP will detect it.
			if err := conn.SetReadDeadline(time.Now().Add(5 * time.Minute)); err != nil {
				logger.Warn("error setting read deadline", "err", err)
				return
			}

			_, _, err := conn.ReadMessage()
			if err != nil {
				if isNormalClose(err) || isTimeout(err) {
					logger.Info("websocket disconnected", "err", err)
				} else {
					logger.Warn("websocket error", "err", err)
				}
				return
			}
		}
	}()

	header := events.EventHeader{Op: events.EvtKindMessage}
	for evt := range evts {
		func() {
			defer func() {
				metrics.RelaySends.WithLabelValues(ident, header.MsgType).Inc()
			}()

			wc, err := conn.NextWriter(websocket.BinaryMessage)
			if err != nil {
				logger.Error("error writing message to relay", "err", err)
				return
			}

			if ctx.Err() != nil {
				logger.Error("context error", "err", err)
				return
			}

			var obj util.CBOR
			switch {
			case evt.Error != nil:
				header.Op = events.EvtKindErrorFrame
				obj = evt.Error
			case evt.RepoCommit != nil:
				header.MsgType = "#commit"
				obj = evt.RepoCommit
			case evt.RepoIdentity != nil:
				header.MsgType = "#identity"
				obj = evt.RepoIdentity
			case evt.RepoAccount != nil:
				header.MsgType = "#account"
				obj = evt.RepoAccount
			case evt.RepoInfo != nil:
				header.MsgType = "#info"
				obj = evt.RepoInfo
			default:
				logger.Warn("unrecognized event kind")
				return
			}

			if err := header.MarshalCBOR(wc); err != nil {
				logger.Error("failed to write header to relay", "err", err)
				return
			}

			if err := obj.MarshalCBOR(wc); err != nil {
				logger.Error("failed to write event to relay", "err", err)
				return
			}

			if err := wc.Close(); err != nil {
				logger.Error("failed to flush-close our event write", "err", err)
				return
			}
		}()
	}

	// we should tell the relay to request a new crawl at this point if we got disconnected
	// use a new context since the old one might be cancelled at this point
	go func() {
		retryCtx, retryCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer retryCancel()
		if err := s.requestCrawl(retryCtx); err != nil {
			logger.Error("error requesting crawls", "err", err)
		}
	}()
}

func isNormalClose(err error) bool {
	if err == nil {
		return false
	}
	// Check if it's a normal close (status codes 1000-1005, etc.)
	// The error message typically contains "close 1000" or similar
	errStr := err.Error()
	return len(errStr) > 8 && errStr[:7] == "websocket: close"
}

func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	// Check if it's a timeout error
	// Using string check as the library doesn't expose error types
	return err.Error() == "i/o timeout"
}
