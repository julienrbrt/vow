package server

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"

	"github.com/ipfs/go-cid"
	"pkg.rbrt.fr/vow/internal/helpers"
	"pkg.rbrt.fr/vow/models"
)

const (
	blockSize = 0x10000
)

type ComAtprotoRepoUploadBlobResponse struct {
	Blob struct {
		Type string `json:"$type"`
		Ref  struct {
			Link string `json:"$link"`
		} `json:"ref"`
		MimeType string `json:"mimeType"`
		Size     int    `json:"size"`
	} `json:"blob"`
}

func (s *Server) handleRepoUploadBlob(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := s.logger.With("name", "handleRepoUploadBlob")

	urepo, _ := getContextValue[*models.RepoActor](r, contextKeyRepo)

	mime := r.Header.Get("content-type")
	if mime == "" {
		mime = "application/octet-stream"
	}

	// Read the entire body into memory. Blobs go straight to IPFS; we don't
	// write any raw bytes to SQLite.
	read := 0
	buf := make([]byte, blockSize)
	fulldata := new(bytes.Buffer)

	for {
		n, err := io.ReadFull(r.Body, buf)
		if err == io.ErrUnexpectedEOF || err == io.EOF {
			if n == 0 {
				break
			}
		} else if err != nil && err != io.ErrUnexpectedEOF {
			logger.Error("error reading blob", "error", err)
			helpers.ServerError(w, nil)
			return
		}

		fulldata.Write(buf[:n])
		read += n

		if n < blockSize {
			break
		}
	}

	c, err := s.addBlobToIPFS(fulldata.Bytes(), mime)
	if err != nil {
		logger.Error("error adding blob to ipfs", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	// If the account has opted into x402 remote pinning and the signer
	// is connected, kick off the payment+pin flow in the
	// background. The blob is already safe on the local Kubo node so this
	// is best-effort — a failure here does not affect the ATProto response.
	if urepo.X402PinningEnabled && s.ipfsConfig.X402 != nil {
		walletAddr := urepo.EthereumAddress()
		if walletAddr == "" {
			logger.Warn("x402 pinning enabled but no public key registered; skipping", "cid", c.String())
		} else if !s.signerHub.IsConnected(urepo.Repo.Did) {
			logger.Warn("x402 pinning enabled but signer not connected; skipping", "cid", c.String())
		} else {
			cidStr := c.String()
			blobSize := read
			go func() {
				pinCtx, cancel := context.WithTimeout(context.Background(), 2*signerRequestTimeout)
				defer cancel()
				if err := s.pinBlobWithX402(pinCtx, urepo.Repo.Did, walletAddr, cidStr, blobSize); err != nil {
					logger.Warn("x402 remote pin failed", "cid", cidStr, "error", err)
				}
			}()
		}
	}

	// Persist a metadata row so we can list blobs by DID, resolve ownership,
	// and track reference counts from records. No blob bytes are stored here.
	blob := models.Blob{
		Did:       urepo.Repo.Did,
		RefCount:  0,
		CreatedAt: s.repoman.clock.Next().String(),
		Cid:       c.Bytes(),
	}

	if err := s.db.Create(ctx, &blob, nil).Error; err != nil {
		logger.Error("error creating blob metadata in db", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	resp := ComAtprotoRepoUploadBlobResponse{}
	resp.Blob.Type = "blob"
	resp.Blob.Ref.Link = c.String()
	resp.Blob.MimeType = mime
	resp.Blob.Size = read

	s.writeJSON(w, 200, resp)
}

// addBlobToIPFS adds raw blob data to the configured IPFS node via the Kubo
// HTTP RPC API (/api/v0/add) and returns the resulting CID.
func (s *Server) addBlobToIPFS(data []byte, mimeType string) (cid.Cid, error) {
	endpoint := s.ipfsConfig.NodeURL + "/api/v0/add?cid-version=1&hash=sha2-256&pin=true&quieter=true"

	body := new(bytes.Buffer)
	writer := multipart.NewWriter(body)

	part, err := writer.CreateFormFile("file", "blob")
	if err != nil {
		return cid.Undef, fmt.Errorf("error creating multipart field: %w", err)
	}

	if _, err := part.Write(data); err != nil {
		return cid.Undef, fmt.Errorf("error writing blob data to multipart: %w", err)
	}

	if err := writer.Close(); err != nil {
		return cid.Undef, fmt.Errorf("error closing multipart writer: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, endpoint, body)
	if err != nil {
		return cid.Undef, fmt.Errorf("error building ipfs add request: %w", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := s.http.Do(req)
	if err != nil {
		return cid.Undef, fmt.Errorf("error calling ipfs add: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(resp.Body)
		return cid.Undef, fmt.Errorf("ipfs add returned status %d: %s", resp.StatusCode, string(msg))
	}

	// Kubo with ?quieter=true returns a single JSON line: {"Hash":"<cid>","Size":"<n>"}
	var result struct {
		Hash string `json:"Hash"`
	}

	if err := readJSON(resp.Body, &result); err != nil {
		return cid.Undef, fmt.Errorf("error decoding ipfs add response: %w", err)
	}

	c, err := cid.Parse(result.Hash)
	if err != nil {
		return cid.Undef, fmt.Errorf("error parsing cid from ipfs add response: %w", err)
	}

	return c, nil
}
