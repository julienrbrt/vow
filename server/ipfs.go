package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
)

// readJSON decodes a single JSON value from r into dst.
func readJSON(r io.Reader, dst any) error {
	return json.NewDecoder(r).Decode(dst)
}

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
