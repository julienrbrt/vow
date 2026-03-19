package server

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/ipfs/boxo/files"
	"github.com/ipfs/go-cid"
	caopts "github.com/ipfs/kubo/core/coreiface/options"
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

	c, err := s.addBlobToIPFS(ctx, fulldata.Bytes())
	if err != nil {
		logger.Error("error adding blob to ipfs", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	// Persist a metadata row so we can list blobs by DID, resolve ownership,
	// and track reference counts from records. No blob bytes are stored here.
	blob := models.Blob{
		Did:       urepo.Repo.Did,
		RefCount:  0,
		CreatedAt: s.repoman.clock.Next().String(),
		Cid:       c.Bytes(),
		MimeType:  mime,
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
// RPC client and returns the resulting CID.
func (s *Server) addBlobToIPFS(ctx context.Context, data []byte) (cid.Cid, error) {
	s.logger.Debug("adding blob to ipfs", "size", len(data))

	p, err := s.ipfsAPI.Unixfs().Add(ctx, files.NewBytesFile(data),
		caopts.Unixfs.CidVersion(1),
	)
	if err != nil {
		return cid.Undef, fmt.Errorf("error adding blob to ipfs: %w", err)
	}

	return p.RootCid(), nil
}
