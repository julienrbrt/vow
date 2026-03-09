package server

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"

	"pkg.rbrt.fr/vow/internal/helpers"
	"pkg.rbrt.fr/vow/models"
	"github.com/ipfs/go-cid"
	"github.com/multiformats/go-multihash"
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

	ipfsUpload := s.ipfsConfig != nil && s.ipfsConfig.BlobstoreEnabled
	storage := "sqlite"
	if ipfsUpload {
		storage = "ipfs"
	}

	blob := models.Blob{
		Did:       urepo.Repo.Did,
		RefCount:  0,
		CreatedAt: s.repoman.clock.Next().String(),
		Storage:   storage,
	}

	if err := s.db.Create(ctx, &blob, nil).Error; err != nil {
		logger.Error("error creating new blob in db", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	read := 0
	part := 0

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

		data := buf[:n]
		read += n
		fulldata.Write(data)

		if !ipfsUpload {
			blobPart := models.BlobPart{
				BlobID: blob.ID,
				Idx:    part,
				Data:   data,
			}

			if err := s.db.Create(ctx, &blobPart, nil).Error; err != nil {
				logger.Error("error adding blob part to db", "error", err)
				helpers.ServerError(w, nil)
				return
			}
		}
		part++

		if n < blockSize {
			break
		}
	}

	c, err := cid.NewPrefixV1(cid.Raw, multihash.SHA2_256).Sum(fulldata.Bytes())
	if err != nil {
		logger.Error("error creating cid prefix", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	if ipfsUpload {
		ipfsCid, err := s.addBlobToIPFS(fulldata.Bytes(), mime)
		if err != nil {
			logger.Error("error adding blob to ipfs", "error", err)
			helpers.ServerError(w, nil)
			return
		}

		// Overwrite the locally computed CID with the one returned by the IPFS
		// node so that retrieval via the gateway uses the correct address.
		c = ipfsCid

		if s.ipfsConfig.PinningServiceURL != "" {
			if err := s.pinBlobToRemote(ctx, ipfsCid.String(), fmt.Sprintf("blob/%s/%s", urepo.Repo.Did, ipfsCid.String())); err != nil {
				// Non-fatal: the blob is already on the local node; log and
				// continue so the upload does not fail.
				logger.Warn("error pinning blob to remote pinning service", "cid", ipfsCid.String(), "error", err)
			}
		}
	}

	if err := s.db.Exec(ctx, "UPDATE blobs SET cid = ? WHERE id = ?", nil, c.Bytes(), blob.ID).Error; err != nil {
		logger.Error("error updating blob", "error", err)
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
	nodeURL := s.ipfsConfig.NodeURL
	if nodeURL == "" {
		nodeURL = "http://127.0.0.1:5001"
	}

	endpoint := nodeURL + "/api/v0/add?cid-version=1&hash=sha2-256&pin=true&quieter=true"

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

	// The Kubo API with ?quieter=true returns a single JSON line:
	// {"Hash":"<cid>","Size":"<n>"}
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
