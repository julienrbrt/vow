package blockstore

import (
	"context"
	"fmt"

	boxoblockstore "github.com/ipfs/boxo/blockstore"
	blocks "github.com/ipfs/go-block-format"
	"github.com/ipfs/go-cid"
)

// RecordingBlockstore wraps a Blockstore and records all reads and writes
// performed against it, for later inspection.
type RecordingBlockstore struct {
	base boxoblockstore.Blockstore

	inserts map[cid.Cid]blocks.Block
	reads   map[cid.Cid]blocks.Block
}

func NewRecording(base boxoblockstore.Blockstore) *RecordingBlockstore {
	return &RecordingBlockstore{
		base:    base,
		inserts: make(map[cid.Cid]blocks.Block),
		reads:   make(map[cid.Cid]blocks.Block),
	}
}

func (bs *RecordingBlockstore) Has(ctx context.Context, c cid.Cid) (bool, error) {
	return bs.base.Has(ctx, c)
}

func (bs *RecordingBlockstore) Get(ctx context.Context, c cid.Cid) (blocks.Block, error) {
	b, err := bs.base.Get(ctx, c)
	if err != nil {
		return nil, err
	}
	bs.reads[c] = b
	return b, nil
}

func (bs *RecordingBlockstore) GetSize(ctx context.Context, c cid.Cid) (int, error) {
	return bs.base.GetSize(ctx, c)
}

func (bs *RecordingBlockstore) DeleteBlock(ctx context.Context, c cid.Cid) error {
	return bs.base.DeleteBlock(ctx, c)
}

func (bs *RecordingBlockstore) Put(ctx context.Context, block blocks.Block) error {
	if err := bs.base.Put(ctx, block); err != nil {
		return err
	}
	bs.inserts[block.Cid()] = block
	return nil
}

func (bs *RecordingBlockstore) PutMany(ctx context.Context, blks []blocks.Block) error {
	if err := bs.base.PutMany(ctx, blks); err != nil {
		return err
	}
	for _, b := range blks {
		bs.inserts[b.Cid()] = b
	}
	return nil
}

func (bs *RecordingBlockstore) AllKeysChan(ctx context.Context) (<-chan cid.Cid, error) {
	return nil, fmt.Errorf("iteration not allowed on recording blockstore")
}

func (bs *RecordingBlockstore) HashOnRead(bool) {}

func (bs *RecordingBlockstore) GetWriteLog() map[cid.Cid]blocks.Block {
	return bs.inserts
}

func (bs *RecordingBlockstore) GetReadLog() []blocks.Block {
	result := make([]blocks.Block, 0, len(bs.reads))
	for _, b := range bs.reads {
		result = append(result, b)
	}
	return result
}
