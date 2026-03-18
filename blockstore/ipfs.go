package blockstore

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"maps"
	"sync"

	"github.com/ipfs/boxo/path"
	blocks "github.com/ipfs/go-block-format"
	"github.com/ipfs/go-cid"
	"github.com/ipfs/kubo/client/rpc"
	caopts "github.com/ipfs/kubo/core/coreiface/options"
)

// IPFSBlockstore stores blocks through Kubo.
type IPFSBlockstore struct {
	did string
	rev string
	cli *rpc.HttpApi

	mu      sync.RWMutex
	inserts map[cid.Cid]blocks.Block
}

// NewIPFS creates a blockstore.
func NewIPFS(did string, cli *rpc.HttpApi) *IPFSBlockstore {
	return &IPFSBlockstore{
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

	p := path.FromCid(c)
	r, err := bs.cli.Block().Get(ctx, p)
	if err != nil {
		return nil, fmt.Errorf("ipfs block/get: %w", err)
	}

	data, err := io.ReadAll(r)
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
	// Use the BlockAPI.Put method which handles CID prefix automatically
	r := bytes.NewReader(blk.RawData())
	pref := blk.Cid().Prefix()

	stat, err := bs.cli.Block().Put(ctx, r,
		caopts.Block.Hash(pref.MhType, pref.MhLength),
		caopts.Block.Pin(true),
	)
	if err != nil {
		return fmt.Errorf("ipfs block/put: %w", err)
	}

	// Verify the returned CID matches
	returnedPath := stat.Path()
	returnedCid, err := cid.Decode(returnedPath.String())
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

	p := path.FromCid(c)
	_, err := bs.cli.Block().Stat(ctx, p)
	if err != nil {
		// Not found error means block doesn't exist
		return false, nil
	}
	return true, nil
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

	// Ignore block removal errors (e.g., block not found)
	p := path.FromCid(c)
	_ = bs.cli.Block().Rm(ctx, p, caopts.Block.Force(true))

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
