package server

import (
	"bytes"
	"fmt"
	"io"
	"net/http"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/ipfs/go-cid"
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

	status := urepo.Status()
	if status != nil {
		if *status == "deactivated" {
			helpers.InputError(w, to.StringPtr("RepoDeactivated"))
			return
		}
	}

	var blob models.Blob
	if err := s.db.Raw(ctx, "SELECT * FROM blobs WHERE did = ? AND cid = ?", nil, did, c.Bytes()).Scan(&blob).Error; err != nil {
		logger.Error("error looking up blob", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	buf := new(bytes.Buffer)

	switch blob.Storage {
	case "sqlite":
		var parts []models.BlobPart
		if err := s.db.Raw(ctx, "SELECT * FROM blob_parts WHERE blob_id = ? ORDER BY idx", nil, blob.ID).Scan(&parts).Error; err != nil {
			logger.Error("error getting blob parts", "error", err)
			helpers.ServerError(w, nil)
			return
		}

		for _, p := range parts {
			buf.Write(p.Data)
		}

	case "ipfs":
		if s.ipfsConfig == nil || !s.ipfsConfig.BlobstoreEnabled {
			logger.Error("ipfs storage disabled")
			helpers.ServerError(w, nil)
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
		data, err := s.fetchBlobFromIPFS(c.String())
		if err != nil {
			logger.Error("error fetching blob from ipfs node", "cid", c.String(), "error", err)
			helpers.ServerError(w, nil)
			return
		}
		buf.Write(data)

	default:
		logger.Error("unknown storage", "storage", blob.Storage)
		helpers.ServerError(w, nil)
		return
	}

	w.Header().Set("Content-Disposition", "attachment; filename="+c.String())
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	io.Copy(w, buf)
}

// fetchBlobFromIPFS retrieves blob data for the given CID from the local Kubo
// node using the HTTP RPC API (/api/v0/cat).
func (s *Server) fetchBlobFromIPFS(cidStr string) ([]byte, error) {
	nodeURL := s.ipfsConfig.NodeURL
	if nodeURL == "" {
		nodeURL = "http://127.0.0.1:5001"
	}

	endpoint := fmt.Sprintf("%s/api/v0/cat?arg=%s", nodeURL, cidStr)

	req, err := http.NewRequest(http.MethodPost, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("error building ipfs cat request: %w", err)
	}

	resp, err := s.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error calling ipfs cat: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("ipfs cat returned status %d: %s", resp.StatusCode, string(msg))
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading ipfs cat response: %w", err)
	}

	return data, nil
}
