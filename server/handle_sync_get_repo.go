package server

import (
	"bytes"
	"context"
	"net/http"

	"github.com/bluesky-social/indigo/carstore"
	boxoblockstore "github.com/ipfs/boxo/blockstore"
	"github.com/ipfs/go-cid"
	cbor "github.com/ipfs/go-ipld-cbor"
	"github.com/ipld/go-car"
	"pkg.rbrt.fr/vow/internal/helpers"
)

func (s *Server) handleSyncGetRepo(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := s.logger.With("name", "handleSyncGetRepo")

	did := r.URL.Query().Get("did")
	if did == "" {
		helpers.InputError(w, nil)
		return
	}

	urepo, err := s.getRepoActorByDid(ctx, did)
	if err != nil {
		logger.Error("could not find repo", "did", did, "error", err)
		helpers.ServerError(w, nil)
		return
	}

	if len(urepo.Root) == 0 {
		logger.Error("repo root is uninitialized", "did", did)
		// 400 is appropriate for RepoNotFound in ATProto
		errStr := "RepoNotFound"
		helpers.InputError(w, &errStr)
		return
	}

	rc, err := cid.Cast(urepo.Root)
	if err != nil {
		logger.Error("error casting root cid", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	hb, err := cbor.DumpObject(&car.CarHeader{
		Roots:   []cid.Cid{rc},
		Version: 1,
	})
	if err != nil {
		logger.Error("error dumping car header", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	buf := new(bytes.Buffer)

	if _, err := carstore.LdWrite(buf, hb); err != nil {
		logger.Error("error writing car header", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	bs := newBlockstoreForRepo(urepo.Repo.Did, s.ipfsAPI)
	if err := writeRepoBlocksFromBlockstore(ctx, buf, bs, rc); err != nil {
		logger.Error("error writing repo blocks to car", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	w.Header().Set("Content-Type", "application/vnd.ipld.car")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(buf.Bytes()); err != nil {
		logger.Error("failed to write response", "error", err)
	}
}

// writeRepoBlocksFromBlockstore walks the repo DAG starting from the commit
// root CID and writes every reachable block into the CAR buffer. It performs a
// breadth-first traversal by parsing each DAG-CBOR block for CID links.
func writeRepoBlocksFromBlockstore(ctx context.Context, buf *bytes.Buffer, bs boxoblockstore.Blockstore, root cid.Cid) error {
	visited := make(map[cid.Cid]struct{})
	queue := []cid.Cid{root}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		if _, seen := visited[current]; seen {
			continue
		}
		visited[current] = struct{}{}

		blk, err := bs.Get(ctx, current)
		if err != nil {
			return err
		}

		if _, err := carstore.LdWrite(buf, blk.Cid().Bytes(), blk.RawData()); err != nil {
			return err
		}

		// Only DAG-CBOR blocks can contain CID links; skip raw blocks.
		if current.Prefix().Codec == cid.DagCBOR {
			links := extractCBORLinks(blk.RawData())
			for _, link := range links {
				if _, seen := visited[link]; !seen {
					queue = append(queue, link)
				}
			}
		}
	}

	return nil
}

// extractCBORLinks scans raw CBOR bytes for embedded CID links (CBOR tag 42).
// This is a lightweight scanner that looks for the tag-42 marker followed by
// a valid CID. It does not fully parse the CBOR structure.
func extractCBORLinks(data []byte) []cid.Cid {
	var links []cid.Cid

	// CBOR tag 42 is used by DAG-CBOR to embed CID links. The encoding is:
	//   0xd8 0x2a  (tag 42 in 1-byte form)
	//   followed by a byte string containing the CID bytes
	for i := 0; i < len(data)-2; i++ {
		if data[i] != 0xd8 || data[i+1] != 0x2a {
			continue
		}

		// The next byte should be a CBOR byte string major type (0x58 for
		// 1-byte length, 0x59 for 2-byte, or 0x40-0x57 for tiny lengths).
		pos := i + 2
		if pos >= len(data) {
			continue
		}

		var bsLen int
		major := data[pos] & 0xe0
		info := data[pos] & 0x1f

		if major != 0x40 {
			continue
		}

		if info < 24 {
			bsLen = int(info)
			pos++
		} else if info == 24 {
			if pos+1 >= len(data) {
				continue
			}
			bsLen = int(data[pos+1])
			pos += 2
		} else if info == 25 {
			if pos+2 >= len(data) {
				continue
			}
			bsLen = int(data[pos+1])<<8 | int(data[pos+2])
			pos += 3
		} else {
			continue
		}

		if pos+bsLen > len(data) || bsLen < 2 {
			continue
		}

		// DAG-CBOR CID links are prefixed with a 0x00 byte (CID multibase
		// identity prefix) that must be stripped before parsing.
		cidBytes := data[pos : pos+bsLen]
		if cidBytes[0] == 0x00 {
			cidBytes = cidBytes[1:]
		}

		c, err := cid.Cast(cidBytes)
		if err != nil {
			continue
		}

		links = append(links, c)
	}

	return links
}
