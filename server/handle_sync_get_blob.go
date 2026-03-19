package server

import (
	"fmt"
	"io"
	"net/http"

	"github.com/ipfs/go-cid"
	"pkg.rbrt.fr/vow/internal/helpers"
	"pkg.rbrt.fr/vow/models"
)

func (s *Server) handleSyncGetBlob(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := s.logger.With("name", "handleSyncGetBlob")

	did := r.URL.Query().Get("did")
	if did == "" {
		helpers.InputError(w, nil)
		return
	}

	cstr := r.URL.Query().Get("cid")
	if cstr == "" {
		helpers.InputError(w, nil)
		return
	}

	c, err := cid.Parse(cstr)
	if err != nil {
		helpers.InputError(w, nil)
		return
	}

	urepo, err := s.getRepoActorByDid(ctx, did)
	if err != nil {
		logger.Error("could not find user for requested blob", "error", err)
		helpers.InputError(w, nil)
		return
	}

	if status := urepo.Status(); status != nil {
		if *status == "deactivated" {
			helpers.InputError(w, new("RepoDeactivated"))
			return
		}
	}

	// Verify this blob is registered to the given DID. We don't store the
	// blob bytes here — just the metadata row that proves ownership.
	var blob models.Blob
	if err := s.db.Raw(ctx, "SELECT * FROM blobs WHERE did = ? AND cid = ?", nil, did, c.Bytes()).Scan(&blob).Error; err != nil {
		logger.Error("error looking up blob", "error", err)
		helpers.ServerError(w, nil)
		return
	}
	if blob.Did == "" {
		helpers.InputError(w, new("BlobNotFound"))
		return
	}

	// If a public gateway is configured, redirect the client directly to it
	// instead of proxying the content through this server.
	if s.ipfsConfig.GatewayURL != "" {
		redirectURL := fmt.Sprintf("%s/ipfs/%s", s.ipfsConfig.GatewayURL, c.String())
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}

	// Otherwise fetch from the local Kubo node via /api/v0/cat and stream
	// the content back to the client.
	nodeURL := s.ipfsConfig.NodeURL
	endpoint := fmt.Sprintf("%s/api/v0/cat?arg=%s", nodeURL, c.String())

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		logger.Error("error building ipfs cat request", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	resp, err := s.http.Do(req)
	if err != nil {
		logger.Error("error calling ipfs cat", "cid", c.String(), "error", err)
		helpers.ServerError(w, nil)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(resp.Body)
		logger.Error("ipfs cat returned error", "cid", c.String(), "status", resp.StatusCode, "body", string(msg))
		helpers.ServerError(w, nil)
		return
	}

	w.Header().Set("Content-Disposition", "attachment; filename="+c.String())
	w.Header().Set("Content-Type", blob.MimeType)
	w.WriteHeader(http.StatusOK)
	if _, err := io.Copy(w, resp.Body); err != nil {
		logger.Error("failed to stream blob response", "error", err)
	}
}
