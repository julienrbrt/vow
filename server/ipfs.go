package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// readJSON decodes a single JSON value from r into dst.
func readJSON(r io.Reader, dst any) error {
	return json.NewDecoder(r).Decode(dst)
}

// pinBlobToRemote pins a CID to the configured remote pinning service using
// the IPFS Pinning Service API spec
// (https://ipfs.github.io/pinning-services-api-spec/).
//
// The call is best-effort: callers should log the error but not treat it as
// fatal so that a transient pinning failure does not prevent a blob upload
// from succeeding.
func (s *Server) pinBlobToRemote(ctx context.Context, cidStr string, name string) error {
	serviceURL := s.ipfsConfig.PinningServiceURL
	token := s.ipfsConfig.PinningServiceToken

	if serviceURL == "" {
		return fmt.Errorf("no pinning service URL configured")
	}

	endpoint := serviceURL + "/pins"

	payload := map[string]any{
		"cid":  cidStr,
		"name": name,
		"meta": map[string]string{
			"pinned_by": "vow",
			"pinned_at": time.Now().UTC().Format(time.RFC3339),
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("error marshalling pin request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("error building pin request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := s.http.Do(req)
	if err != nil {
		return fmt.Errorf("error calling pinning service: %w", err)
	}
	defer resp.Body.Close()

	// The Pinning Service API returns 202 Accepted on success.
	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("pinning service returned status %d: %s", resp.StatusCode, string(msg))
	}

	return nil
}
