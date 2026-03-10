package blockstore

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"mime/multipart"
	"net/http"
	"sync"

	blocks "github.com/ipfs/go-block-format"
	"github.com/ipfs/go-cid"
)

// IPFSBlockstore stores blocks through Kubo.
type IPFSBlockstore struct {
	nodeURL string
	did     string
	rev     string
	cli     *http.Client

	mu      sync.RWMutex
	inserts map[cid.Cid]blocks.Block
}

// NewIPFS creates a blockstore.
func NewIPFS(did string, nodeURL string, cli *http.Client) *IPFSBlockstore {
	if nodeURL == "" {
		nodeURL = "http://127.0.0.1:5001"
	}
	if cli == nil {
		cli = http.DefaultClient
	}
	return &IPFSBlockstore{
		nodeURL: nodeURL,
		did:     did,
		cli:     cli,
		inserts: make(map[cid.Cid]blocks.Block),
	}
}

// SetRev stores the revision.
func (bs *IPFSBlockstore) SetRev(rev string) {
	bs.rev = rev
}

// Get returns a block by CID.
func (bs *IPFSBlockstore) Get(ctx context.Context, c cid.Cid) (blocks.Block, error) {
	bs.mu.RLock()
	if blk, ok := bs.inserts[c]; ok {
		bs.mu.RUnlock()
		return blk, nil
	}
	bs.mu.RUnlock()

	endpoint := fmt.Sprintf("%s/api/v0/block/get?arg=%s", bs.nodeURL, c.String())

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("ipfs block/get: building request: %w", err)
	}

	resp, err := bs.cli.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ipfs block/get: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("ipfs block/get returned %d: %s", resp.StatusCode, string(body))
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("ipfs block/get: reading body: %w", err)
	}

	blk, err := blocks.NewBlockWithCid(data, c)
	if err != nil {
		return nil, fmt.Errorf("ipfs block/get: creating block: %w", err)
	}

	return blk, nil
}

// Put stores one block.
func (bs *IPFSBlockstore) Put(ctx context.Context, block blocks.Block) error {
	bs.mu.Lock()
	bs.inserts[block.Cid()] = block
	bs.mu.Unlock()

	if err := bs.putToIPFS(ctx, block); err != nil {
		return err
	}

	return nil
}

// PutMany stores multiple blocks.
func (bs *IPFSBlockstore) PutMany(ctx context.Context, blks []blocks.Block) error {
	for _, blk := range blks {
		bs.mu.Lock()
		bs.inserts[blk.Cid()] = blk
		bs.mu.Unlock()

		if err := bs.putToIPFS(ctx, blk); err != nil {
			return err
		}
	}
	return nil
}

func (bs *IPFSBlockstore) putToIPFS(ctx context.Context, blk blocks.Block) error {
	// Keep the same CID.
	pref := blk.Cid().Prefix()

	codecName, err := codecToName(pref.Codec)
	if err != nil {
		return err
	}
	mhName, err := mhtypeToName(pref.MhType)
	if err != nil {
		return err
	}

	endpoint := fmt.Sprintf(
		"%s/api/v0/block/put?cid-codec=%s&mhtype=%s&mhlen=%d&pin=true",
		bs.nodeURL, codecName, mhName, pref.MhLength,
	)

	body := new(bytes.Buffer)
	writer := multipart.NewWriter(body)

	part, err := writer.CreateFormFile("data", "block")
	if err != nil {
		return fmt.Errorf("ipfs block/put: creating multipart: %w", err)
	}

	if _, err := part.Write(blk.RawData()); err != nil {
		return fmt.Errorf("ipfs block/put: writing data: %w", err)
	}

	if err := writer.Close(); err != nil {
		return fmt.Errorf("ipfs block/put: closing writer: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, body)
	if err != nil {
		return fmt.Errorf("ipfs block/put: building request: %w", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := bs.cli.Do(req)
	if err != nil {
		return fmt.Errorf("ipfs block/put: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("ipfs block/put returned %d: %s", resp.StatusCode, string(msg))
	}

	// Verify the returned CID.
	var result struct {
		Key  string `json:"Key"`
		Size int    `json:"Size"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("ipfs block/put: decoding response: %w", err)
	}

	returnedCid, err := cid.Decode(result.Key)
	if err != nil {
		return fmt.Errorf("ipfs block/put: parsing returned CID: %w", err)
	}

	if !returnedCid.Equals(blk.Cid()) {
		return fmt.Errorf("ipfs block/put: CID mismatch: expected %s, got %s", blk.Cid(), returnedCid)
	}

	return nil
}

// Has reports whether a block exists.
func (bs *IPFSBlockstore) Has(ctx context.Context, c cid.Cid) (bool, error) {
	bs.mu.RLock()
	if _, ok := bs.inserts[c]; ok {
		bs.mu.RUnlock()
		return true, nil
	}
	bs.mu.RUnlock()

	endpoint := fmt.Sprintf("%s/api/v0/block/stat?arg=%s", bs.nodeURL, c.String())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		return false, err
	}

	resp, err := bs.cli.Do(req)
	if err != nil {
		return false, err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	return resp.StatusCode == http.StatusOK, nil
}

// GetSize returns the size.
func (bs *IPFSBlockstore) GetSize(ctx context.Context, c cid.Cid) (int, error) {
	blk, err := bs.Get(ctx, c)
	if err != nil {
		return 0, err
	}
	return len(blk.RawData()), nil
}

// DeleteBlock removes a block from the cache and unpins it.
func (bs *IPFSBlockstore) DeleteBlock(ctx context.Context, c cid.Cid) error {
	bs.mu.Lock()
	delete(bs.inserts, c)
	bs.mu.Unlock()

	// Ignore unpin errors.
	endpoint := fmt.Sprintf("%s/api/v0/pin/rm?arg=%s", bs.nodeURL, c.String())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		return nil
	}
	resp, err := bs.cli.Do(req)
	if err != nil {
		return nil
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	return nil
}

// AllKeysChan is unsupported.
func (bs *IPFSBlockstore) AllKeysChan(ctx context.Context) (<-chan cid.Cid, error) {
	return nil, fmt.Errorf("iteration not supported on IPFS blockstore")
}

// HashOnRead is a no-op.
func (bs *IPFSBlockstore) HashOnRead(bool) {}

// GetWriteLog returns written blocks.
func (bs *IPFSBlockstore) GetWriteLog() map[cid.Cid]blocks.Block {
	bs.mu.RLock()
	defer bs.mu.RUnlock()

	out := make(map[cid.Cid]blocks.Block, len(bs.inserts))
	maps.Copy(out, bs.inserts)
	return out
}

// codecToName converts a CID codec to a Kubo name.
func codecToName(codec uint64) (string, error) {
	switch codec {
	case cid.DagCBOR:
		return "dag-cbor", nil
	case cid.DagProtobuf:
		return "dag-pb", nil
	case cid.Raw:
		return "raw", nil
	case cid.DagJSON:
		return "dag-json", nil
	default:
		return fmt.Sprintf("0x%x", codec), nil
	}
}

// mhtypeToName converts a multihash type to its name.
func mhtypeToName(mhtype uint64) (string, error) {
	switch mhtype {
	case 0x12: // sha2-256
		return "sha2-256", nil
	case 0x13: // sha2-512
		return "sha2-512", nil
	case 0x14: // sha3-512
		return "sha3-512", nil
	case 0x15: // sha3-384
		return "sha3-384", nil
	case 0x16: // sha3-256
		return "sha3-256", nil
	case 0x1e: // blake3
		return "blake3", nil
	case 0x00: // identity
		return "identity", nil
	default:
		return "", fmt.Errorf("unsupported multihash type: 0x%x", mhtype)
	}
}
