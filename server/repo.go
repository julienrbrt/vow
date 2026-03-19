package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/bluesky-social/indigo/api/atproto"
	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/bluesky-social/indigo/atproto/atdata"
	atp "github.com/bluesky-social/indigo/atproto/repo"
	"github.com/bluesky-social/indigo/atproto/repo/mst"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/bluesky-social/indigo/carstore"
	"github.com/bluesky-social/indigo/events"
	lexutil "github.com/bluesky-social/indigo/lex/util"
	"github.com/google/uuid"
	blockstore "github.com/ipfs/boxo/blockstore"
	blocks "github.com/ipfs/go-block-format"
	"github.com/ipfs/go-cid"
	legacyblockstore "github.com/ipfs/go-ipfs-blockstore" //nolint:staticcheck
	cbor "github.com/ipfs/go-ipld-cbor"
	"github.com/ipld/go-car"
	"github.com/multiformats/go-multihash"
	"gorm.io/gorm/clause"
	"pkg.rbrt.fr/vow/internal/db"
	"pkg.rbrt.fr/vow/metrics"
	"pkg.rbrt.fr/vow/models"
)

type cachedRepo struct {
	mu   sync.Mutex
	repo *atp.Repo
	root cid.Cid
}

type RepoMan struct {
	db    *db.DB
	s     *Server
	clock *syntax.TIDClock

	cacheMu sync.Mutex
	cache   map[string]*cachedRepo
}

func NewRepoMan(s *Server) *RepoMan {
	clock := syntax.NewTIDClock(0)

	return &RepoMan{
		s:     s,
		db:    s.db,
		clock: clock,
		cache: make(map[string]*cachedRepo),
	}
}

func (rm *RepoMan) withRepo(ctx context.Context, did string, rootCid cid.Cid, bs blockstore.Blockstore, fn func(r *atp.Repo) (newRoot cid.Cid, err error)) error {
	rm.cacheMu.Lock()
	cr, ok := rm.cache[did]
	if !ok {
		cr = &cachedRepo{}
		rm.cache[did] = cr
	}
	rm.cacheMu.Unlock()

	cr.mu.Lock()
	defer cr.mu.Unlock()

	if cr.repo == nil || cr.root != rootCid {
		r, err := openRepo(ctx, bs, rootCid, did)
		if err != nil {
			return err
		}
		cr.repo = r
		cr.root = rootCid
	}

	newRoot, err := fn(cr.repo)
	if err != nil {
		// invalidate on error since the tree may be partially mutated
		cr.repo = nil
		cr.root = cid.Undef
		return err
	}

	cr.root = newRoot
	return nil
}

type OpType string

var (
	OpTypeCreate = OpType("com.atproto.repo.applyWrites#create")
	OpTypeUpdate = OpType("com.atproto.repo.applyWrites#update")
	OpTypeDelete = OpType("com.atproto.repo.applyWrites#delete")
)

func (ot OpType) String() string {
	return string(ot)
}

type Op struct {
	Type       OpType          `json:"$type"`
	Collection string          `json:"collection"`
	Rkey       *string         `json:"rkey,omitempty"`
	Validate   *bool           `json:"validate,omitempty"`
	SwapRecord *string         `json:"swapRecord,omitempty"`
	Record     *MarshalableMap `json:"record,omitempty"`
}

type MarshalableMap map[string]any

type FirehoseOp struct {
	Cid    cid.Cid
	Path   string
	Action string
}

func (mm *MarshalableMap) MarshalCBOR(w io.Writer) error {
	data, err := atdata.MarshalCBOR(*mm)
	if err != nil {
		return err
	}

	_, err = w.Write(data)
	return err
}

type ApplyWriteResult struct {
	Type             *string     `json:"$type,omitempty"`
	Uri              *string     `json:"uri,omitempty"`
	Cid              *string     `json:"cid,omitempty"`
	Commit           *RepoCommit `json:"commit,omitempty"`
	ValidationStatus *string     `json:"validationStatus,omitempty"`
}

type RepoCommit struct {
	Cid string `json:"cid"`
	Rev string `json:"rev"`
}

func openRepo(ctx context.Context, bs blockstore.Blockstore, rootCid cid.Cid, did string) (*atp.Repo, error) {
	commitBlock, err := bs.Get(ctx, rootCid)
	if err != nil {
		return nil, fmt.Errorf("reading commit block: %w", err)
	}

	var commit atp.Commit
	if err := commit.UnmarshalCBOR(bytes.NewReader(commitBlock.RawData())); err != nil {
		return nil, fmt.Errorf("parsing commit block: %w", err)
	}

	tree, err := mst.LoadTreeFromStore(ctx, bs, commit.Data)
	if err != nil {
		return nil, fmt.Errorf("loading MST: %w", err)
	}

	clk := syntax.ClockFromTID(syntax.TID(commit.Rev))
	return &atp.Repo{
		DID:         syntax.DID(did),
		Clock:       &clk,
		MST:         *tree,
		RecordStore: bs,
	}, nil
}

// revSetter is implemented by blockstores that can be told the current repo
// revision before blocks are written (so the Rev column is stamped correctly).
type revSetter interface {
	SetRev(rev string)
}

// unsignedCommit is the intermediate product of buildUnsignedCommit. It holds
// the serialised commit CBOR (without a sig field) plus the rev string, ready
// for the user to sign. Once the signature arrives, finaliseCommit uses this
// to produce the final commit block.
type unsignedCommit struct {
	// cbor is the canonical CBOR encoding of the commit struct with Sig == "".
	// This is the byte slice the user must sign.
	cbor []byte
	rev  string
}

// buildUnsignedCommit advances the repo's MST, serialises the commit struct
// with an empty signature, stamps the rev on the blockstore, and writes the
// MST diff blocks — but does NOT write the commit block itself and does NOT
// require a signing key. The caller must obtain a signature over uc.cbor and
// then call finaliseCommit.
func buildUnsignedCommit(ctx context.Context, bs blockstore.Blockstore, r *atp.Repo) (*unsignedCommit, error) {
	commit, err := r.Commit()
	if err != nil {
		return nil, fmt.Errorf("creating commit: %w", err)
	}

	// Stamp the revision on the blockstore before writing any MST blocks so
	// that every block carries the correct Rev.
	if rs, ok := bs.(revSetter); ok {
		rs.SetRev(commit.Rev)
	}

	if _, err := r.MST.WriteDiffBlocks(ctx, bs.(legacyblockstore.Blockstore)); err != nil { //nolint:staticcheck
		return nil, fmt.Errorf("writing MST blocks: %w", err)
	}

	buf := new(bytes.Buffer)
	if err := commit.MarshalCBOR(buf); err != nil {
		return nil, fmt.Errorf("marshaling commit: %w", err)
	}

	return &unsignedCommit{cbor: buf.Bytes(), rev: commit.Rev}, nil
}

// finaliseCommit takes a previously built unsignedCommit, attaches the
// provided raw signature bytes, reserialises the commit, writes the commit
// block to the blockstore, and returns the commit CID.
//
// sig must be the raw 64-byte (r‖s) P-256 ECDSA signature over uc.cbor as
// produced by the passkey WebAuthn assertion and verified by the WS handler.
func finaliseCommit(ctx context.Context, bs blockstore.Blockstore, uc *unsignedCommit, sig []byte) (cid.Cid, error) {
	// Decode the unsigned commit so we can attach the signature field.
	var commit atp.Commit
	if err := commit.UnmarshalCBOR(bytes.NewReader(uc.cbor)); err != nil {
		return cid.Undef, fmt.Errorf("unmarshaling unsigned commit: %w", err)
	}

	commit.Sig = sig

	buf := new(bytes.Buffer)
	if err := commit.MarshalCBOR(buf); err != nil {
		return cid.Undef, fmt.Errorf("marshaling signed commit: %w", err)
	}

	pref := cid.NewPrefixV1(cid.DagCBOR, multihash.SHA2_256)
	commitCid, err := pref.Sum(buf.Bytes())
	if err != nil {
		return cid.Undef, fmt.Errorf("computing commit CID: %w", err)
	}

	blk, err := blocks.NewBlockWithCid(buf.Bytes(), commitCid)
	if err != nil {
		return cid.Undef, fmt.Errorf("creating commit block: %w", err)
	}
	if err := bs.Put(ctx, blk); err != nil {
		return cid.Undef, fmt.Errorf("writing commit block: %w", err)
	}

	// Verify the commit block and MST root were persisted to IPFS (bypassing local cache)
	if verifier, ok := bs.(interface {
		Verify(context.Context, cid.Cid) error
	}); ok {
		if err := verifier.Verify(ctx, commitCid); err != nil {
			return cid.Undef, fmt.Errorf("verifying commit block persisted: %w", err)
		}
		if err := verifier.Verify(ctx, commit.Data); err != nil {
			return cid.Undef, fmt.Errorf("verifying MST root block persisted: %w", err)
		}
	}

	return commitCid, nil
}

// commitRepo is kept for the initial-account-creation path where we need to
// produce a genesis commit signed by the rotation key (before any BYOK key is
// registered). It must NOT be used for any user-initiated write.
func commitRepo(ctx context.Context, bs blockstore.Blockstore, r *atp.Repo, signingKey []byte) (cid.Cid, string, error) {
	uc, err := buildUnsignedCommit(ctx, bs, r)
	if err != nil {
		return cid.Undef, "", err
	}

	privkey, err := atcrypto.ParsePrivateBytesK256(signingKey)
	if err != nil {
		return cid.Undef, "", fmt.Errorf("parsing signing key: %w", err)
	}

	sig, err := privkey.HashAndSign(uc.cbor)
	if err != nil {
		return cid.Undef, "", fmt.Errorf("signing commit: %w", err)
	}

	commitCid, err := finaliseCommit(ctx, bs, uc, sig)
	if err != nil {
		return cid.Undef, "", err
	}

	return commitCid, uc.rev, nil
}

func putRecordBlock(ctx context.Context, bs blockstore.Blockstore, rec *MarshalableMap) (cid.Cid, error) {
	buf := new(bytes.Buffer)
	if err := rec.MarshalCBOR(buf); err != nil {
		return cid.Undef, err
	}

	pref := cid.NewPrefixV1(cid.DagCBOR, multihash.SHA2_256)
	c, err := pref.Sum(buf.Bytes())
	if err != nil {
		return cid.Undef, err
	}

	blk, err := blocks.NewBlockWithCid(buf.Bytes(), c)
	if err != nil {
		return cid.Undef, err
	}
	if err := bs.Put(ctx, blk); err != nil {
		return cid.Undef, err
	}

	return c, nil
}

// TODO make use of swap commit
// pendingCommitState captures everything produced by the MST-building phase of
// applyWrites that is needed to finalise the commit once a signature arrives.
// It is held in memory and passed directly to finaliseWriteFromState after the
// SignerHub WebSocket round-trip completes.
//
// NOTE: block data is stored as raw bytes slices (base64 in JSON) because CIDs
// and block objects are not JSON-serialisable out of the box with the standard
// library. We store them as parallel slices keyed by index.
type pendingCommitState struct {
	Did          string          `json:"did"`
	PrevRev      string          `json:"prevRev"`
	PrevRoot     []byte          `json:"prevRoot"`
	UnsignedCBOR []byte          `json:"unsignedCbor"`
	Rev          string          `json:"rev"`
	Entries      []models.Record `json:"entries"`
	// ATPOps mirrors the atp.Operation slice but only the fields we need for
	// the firehose (Path, Value CID bytes, Prev CID bytes, action string).
	ATPOps  []serialisedOp     `json:"atpOps"`
	Results []ApplyWriteResult `json:"results"`
	// WriteLog holds the raw block data from RecordingBlockstore.GetWriteLog(),
	// serialised as {cid, data} pairs so we can replay them into the blockstore.
	WriteLog []serialisedBlock `json:"writeLog"`
}

type serialisedOp struct {
	Path   string `json:"path"`
	Action string `json:"action"`
	Value  []byte `json:"value,omitempty"` // CID bytes for create/update
	Prev   []byte `json:"prev,omitempty"`  // CID bytes for delete
}

type serialisedBlock struct {
	CID  []byte `json:"cid"`
	Data []byte `json:"data"`
}

// applyWrites builds the MST diff for the given operations, requests a
// signature from the user's signer over the unsigned commit bytes,
// and — once the signature is received — finalises and persists the commit.
//
// The function blocks until the signature arrives (up to signerRequestTimeout)
// or an error occurs. Standard ATProto clients see a normal (slightly slower)
// response; the signing round-trip is invisible to them.
func (rm *RepoMan) applyWrites(ctx context.Context, urepo models.Repo, writes []Op, swapCommit *string) ([]ApplyWriteResult, error) {
	rootcid, err := cid.Cast(urepo.Root)
	if err != nil {
		return nil, err
	}

	bs, baseBS := newRecordingBlockstoreForRepo(urepo.Did, rm.s.ipfsAPI)
	// dbs is the unwrapped base blockstore used for direct reads when building
	// the firehose CAR slice.
	dbs := baseBS

	var results []ApplyWriteResult
	var atpOps []*atp.Operation
	var entries []models.Record
	var uc *unsignedCommit

	// ── Phase 1: build MST diff and unsigned commit ───────────────────────
	if err := rm.withRepo(ctx, urepo.Did, rootcid, bs, func(r *atp.Repo) (cid.Cid, error) {
		entries = make([]models.Record, 0, len(writes))
		for i, op := range writes {
			// updates or deletes must supply an rkey
			if op.Type != OpTypeCreate && op.Rkey == nil {
				return cid.Undef, fmt.Errorf("invalid rkey")
			} else if op.Type == OpTypeCreate && op.Rkey != nil {
				// convert to update if the rkey already exists
				path := fmt.Sprintf("%s/%s", op.Collection, *op.Rkey)
				existing, _ := r.MST.Get([]byte(path))
				if existing != nil {
					op.Type = OpTypeUpdate
				}
			} else if op.Rkey == nil {
				// generates rkey for creates that don't supply one
				op.Rkey = new(rm.clock.Next().String())
				writes[i].Rkey = op.Rkey
			}

			path := fmt.Sprintf("%s/%s", op.Collection, *op.Rkey)

			_, err := syntax.ParseRecordKey(*op.Rkey)
			if err != nil {
				return cid.Undef, err
			}

			switch op.Type {
			case OpTypeCreate:
				b, err := json.Marshal(*op.Record)
				if err != nil {
					return cid.Undef, err
				}
				out, err := atdata.UnmarshalJSON(b)
				if err != nil {
					return cid.Undef, err
				}
				mm := MarshalableMap(out)

				if mm["$type"] == "" {
					mm["$type"] = op.Collection
				}

				nc, err := putRecordBlock(ctx, bs, &mm)
				if err != nil {
					return cid.Undef, err
				}

				atpOp, err := atp.ApplyOp(&r.MST, path, &nc)
				if err != nil {
					return cid.Undef, err
				}
				atpOps = append(atpOps, atpOp)

				d, err := atdata.MarshalCBOR(mm)
				if err != nil {
					return cid.Undef, err
				}

				entries = append(entries, models.Record{
					Did:       urepo.Did,
					CreatedAt: rm.clock.Next().String(),
					Nsid:      op.Collection,
					Rkey:      *op.Rkey,
					Cid:       nc.String(),
					Value:     d,
				})

				results = append(results, ApplyWriteResult{
					Type:             new(OpTypeCreate.String()),
					Uri:              new("at://" + urepo.Did + "/" + op.Collection + "/" + *op.Rkey),
					Cid:              new(nc.String()),
					ValidationStatus: new("valid"),
				})

			case OpTypeDelete:
				var old models.Record
				if err := rm.db.Raw(ctx, "SELECT value FROM records WHERE did = ? AND nsid = ? AND rkey = ?", nil, urepo.Did, op.Collection, op.Rkey).Scan(&old).Error; err != nil {
					return cid.Undef, err
				}

				entries = append(entries, models.Record{
					Did:   urepo.Did,
					Nsid:  op.Collection,
					Rkey:  *op.Rkey,
					Value: old.Value,
				})

				atpOp, err := atp.ApplyOp(&r.MST, path, nil)
				if err != nil {
					return cid.Undef, err
				}
				atpOps = append(atpOps, atpOp)

				results = append(results, ApplyWriteResult{
					Type: new(OpTypeDelete.String()),
				})

			case OpTypeUpdate:
				b, err := json.Marshal(*op.Record)
				if err != nil {
					return cid.Undef, err
				}
				out, err := atdata.UnmarshalJSON(b)
				if err != nil {
					return cid.Undef, err
				}
				mm := MarshalableMap(out)

				nc, err := putRecordBlock(ctx, bs, &mm)
				if err != nil {
					return cid.Undef, err
				}

				atpOp, err := atp.ApplyOp(&r.MST, path, &nc)
				if err != nil {
					return cid.Undef, err
				}
				atpOps = append(atpOps, atpOp)

				d, err := atdata.MarshalCBOR(mm)
				if err != nil {
					return cid.Undef, err
				}

				entries = append(entries, models.Record{
					Did:       urepo.Did,
					CreatedAt: rm.clock.Next().String(),
					Nsid:      op.Collection,
					Rkey:      *op.Rkey,
					Cid:       nc.String(),
					Value:     d,
				})

				results = append(results, ApplyWriteResult{
					Type:             new(OpTypeUpdate.String()),
					Uri:              new("at://" + urepo.Did + "/" + op.Collection + "/" + *op.Rkey),
					Cid:              new(nc.String()),
					ValidationStatus: new("valid"),
				})
			}
		}

		// Build the unsigned commit (writes MST diff blocks to bs).
		var commitErr error
		uc, commitErr = buildUnsignedCommit(ctx, bs, r)
		if commitErr != nil {
			return cid.Undef, commitErr
		}

		// Return the previous root CID; withRepo updates its cache only after
		// the final newroot is known (set after signature). We return Undef
		// here to intentionally invalidate the cache so the next call reloads
		// from the blockstore with the real signed root.
		return cid.Undef, nil
	}); err != nil {
		return nil, err
	}

	// ── Phase 2: serialise the write log so we can replay it ─────────────
	writeLog := bs.GetWriteLog()
	sBlocks := make([]serialisedBlock, 0, len(writeLog))
	for _, blk := range writeLog {
		sBlocks = append(sBlocks, serialisedBlock{
			CID:  blk.Cid().Bytes(),
			Data: blk.RawData(),
		})
	}

	sOps := make([]serialisedOp, 0, len(atpOps))
	for _, op := range atpOps {
		sop := serialisedOp{Path: op.Path}
		switch {
		case op.IsCreate():
			sop.Action = "create"
			sop.Value = (*op.Value).Bytes()
		case op.IsUpdate():
			sop.Action = "update"
			sop.Value = (*op.Value).Bytes()
		case op.IsDelete():
			sop.Action = "delete"
			sop.Prev = (*op.Prev).Bytes()
		}
		sOps = append(sOps, sop)
	}

	state := pendingCommitState{
		Did:          urepo.Did,
		PrevRev:      urepo.Rev,
		PrevRoot:     urepo.Root,
		UnsignedCBOR: uc.cbor,
		Rev:          uc.rev,
		Entries:      entries,
		ATPOps:       sOps,
		Results:      results,
		WriteLog:     sBlocks,
	}

	// ── Phase 3: request signature from the signer ───────────────────────
	requestID := uuid.NewString()
	expiresAt := time.Now().Add(signerRequestTimeout)

	// Build human-readable op summaries for the sign_request message.
	pendingOps := make([]PendingWriteOp, 0, len(writes))
	for _, w := range writes {
		rkey := ""
		if w.Rkey != nil {
			rkey = *w.Rkey
		}
		pendingOps = append(pendingOps, PendingWriteOp{
			Type:       string(w.Type),
			Collection: w.Collection,
			Rkey:       rkey,
		})
	}

	payloadB64 := base64.RawURLEncoding.EncodeToString(uc.cbor)
	msgBytes, err := buildSignRequestMsg(requestID, urepo.Did, payloadB64, pendingOps, expiresAt)
	if err != nil {
		return nil, fmt.Errorf("building sign request message: %w", err)
	}

	// Use a child context with the signing deadline so RequestSignature
	// returns promptly if the signer is slow.
	signCtx, cancel := context.WithDeadline(ctx, expiresAt)
	defer cancel()

	sigBytes, err := rm.s.signerHub.RequestSignature(signCtx, urepo.Did, requestID, msgBytes)
	if err != nil {
		return nil, err
	}

	// ── Phase 4: verify the signature ─────────────────────────────────────
	if len(urepo.SigningPublicKey) == 0 {
		return nil, fmt.Errorf("no public key registered for account %s", urepo.Did)
	}

	pubKey, err := atcrypto.ParsePublicBytesK256(urepo.SigningPublicKey)
	if err != nil {
		return nil, fmt.Errorf("parsing stored public key: %w", err)
	}

	if err := pubKey.HashAndVerifyLenient(uc.cbor, sigBytes); err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	// ── Phase 5: finalise and persist the commit ───────────────────────────
	return rm.finaliseWriteFromState(ctx, urepo, &state, sigBytes, dbs)
}

// finaliseWriteFromState takes a pendingCommitState and a verified signature,
// finalises the commit block, persists records, fires the firehose event, and
// updates the repo root. It is shared between the inline applyWrites path and
// (in the future) any async retry path.
func (rm *RepoMan) finaliseWriteFromState(
	ctx context.Context,
	urepo models.Repo,
	state *pendingCommitState,
	sigBytes []byte,
	dbs blockstore.Blockstore,
) ([]ApplyWriteResult, error) {
	bs, _ := newRecordingBlockstoreForRepo(urepo.Did, rm.s.ipfsAPI)

	// Replay the write log blocks into the fresh blockstore so finaliseCommit
	// can locate them when building the CAR.
	for _, sb := range state.WriteLog {
		c, err := cid.Cast(sb.CID)
		if err != nil {
			return nil, fmt.Errorf("replaying write log, bad CID: %w", err)
		}
		blk, err := blocks.NewBlockWithCid(sb.Data, c)
		if err != nil {
			return nil, fmt.Errorf("replaying write log, bad block: %w", err)
		}
		if err := bs.Put(ctx, blk); err != nil {
			return nil, fmt.Errorf("replaying write log, put failed: %w", err)
		}
	}

	uc := &unsignedCommit{cbor: state.UnsignedCBOR, rev: state.Rev}
	newroot, err := finaliseCommit(ctx, bs, uc, sigBytes)
	if err != nil {
		return nil, err
	}

	results := state.Results
	for _, result := range results {
		if result.Type != nil {
			metrics.RepoOperations.WithLabelValues(*result.Type).Inc()
		}
	}

	// Build the firehose CAR buffer.
	buf := new(bytes.Buffer)
	hb, err := cbor.DumpObject(&car.CarHeader{
		Roots:   []cid.Cid{newroot},
		Version: 1,
	})
	if err != nil {
		return nil, fmt.Errorf("error dumping car header: %w", err)
	}
	if _, err := carstore.LdWrite(buf, hb); err != nil {
		return nil, err
	}

	repoOps := make([]*atproto.SyncSubscribeRepos_RepoOp, 0, len(state.ATPOps))
	for _, sop := range state.ATPOps {
		switch sop.Action {
		case "create", "update":
			c, err := cid.Cast(sop.Value)
			if err != nil {
				return nil, fmt.Errorf("bad value CID in serialised op: %w", err)
			}
			ll := lexutil.LexLink(c)
			repoOps = append(repoOps, &atproto.SyncSubscribeRepos_RepoOp{
				Action: sop.Action,
				Path:   sop.Path,
				Cid:    &ll,
			})
			blk, err := dbs.Get(ctx, c)
			if err != nil {
				return nil, err
			}
			if _, err := carstore.LdWrite(buf, blk.Cid().Bytes(), blk.RawData()); err != nil {
				return nil, err
			}
		case "delete":
			c, err := cid.Cast(sop.Prev)
			if err != nil {
				return nil, fmt.Errorf("bad prev CID in serialised op: %w", err)
			}
			ll := lexutil.LexLink(c)
			repoOps = append(repoOps, &atproto.SyncSubscribeRepos_RepoOp{
				Action: "delete",
				Path:   sop.Path,
				Cid:    nil,
				Prev:   &ll,
			})
			blk, err := dbs.Get(ctx, c)
			if err != nil {
				return nil, err
			}
			if _, err := carstore.LdWrite(buf, blk.Cid().Bytes(), blk.RawData()); err != nil {
				return nil, err
			}
		}
	}

	// Write log blocks into CAR.
	for _, sb := range state.WriteLog {
		c, err := cid.Cast(sb.CID)
		if err != nil {
			return nil, err
		}
		if _, err := carstore.LdWrite(buf, c.Bytes(), sb.Data); err != nil {
			return nil, err
		}
	}

	// Persist records and handle blob ref-counting.
	var blobs []lexutil.LexLink
	for _, entry := range state.Entries {
		var cids []cid.Cid
		if entry.Cid != "" {
			if err := rm.s.db.Create(ctx, &entry, []clause.Expression{clause.OnConflict{
				Columns:   []clause.Column{{Name: "did"}, {Name: "nsid"}, {Name: "rkey"}},
				UpdateAll: true,
			}}).Error; err != nil {
				return nil, err
			}
			cids, err = rm.incrementBlobRefs(ctx, urepo, entry.Value)
			if err != nil {
				return nil, err
			}
		} else {
			if err := rm.s.db.Delete(ctx, &entry, nil).Error; err != nil {
				return nil, err
			}
			cids, err = rm.decrementBlobRefs(ctx, urepo, entry.Value)
			if err != nil {
				return nil, err
			}
		}
		for _, c := range cids {
			blobs = append(blobs, lexutil.LexLink(c))
		}
	}

	if err := rm.s.evtman.AddEvent(context.Background(), &events.XRPCStreamEvent{
		RepoCommit: &atproto.SyncSubscribeRepos_Commit{
			Repo:   urepo.Did,
			Blocks: buf.Bytes(),
			Blobs:  blobs,
			Rev:    state.Rev,
			Since:  &state.PrevRev,
			Commit: lexutil.LexLink(newroot),
			Time:   time.Now().Format(time.RFC3339Nano),
			Ops:    repoOps,
			TooBig: false,
		},
	}); err != nil {
		rm.s.logger.Error("failed to add event", "error", err)
	}

	if err := rm.s.UpdateRepo(ctx, urepo.Did, newroot, state.Rev); err != nil {
		return nil, err
	}

	for i := range results {
		results[i].Type = new(*results[i].Type + "Result")
		results[i].Commit = &RepoCommit{
			Cid: newroot.String(),
			Rev: state.Rev,
		}
	}

	return results, nil
}

func (rm *RepoMan) getRecordProof(ctx context.Context, urepo models.Repo, collection, rkey string) (cid.Cid, []blocks.Block, error) {
	commitCid, err := cid.Cast(urepo.Root)
	if err != nil {
		return cid.Undef, nil, err
	}

	var proofBlocks []blocks.Block
	var recordCid *cid.Cid

	dbs := newBlockstoreForRepo(urepo.Did, rm.s.ipfsAPI)

	if err := rm.withRepo(ctx, urepo.Did, commitCid, dbs, func(r *atp.Repo) (cid.Cid, error) {
		path := collection + "/" + rkey

		// walk the cached in-memory tree to find the record and collect MST node CIDs on the path
		nodeCIDs := collectPathNodeCIDs(r.MST.Root, []byte(path))

		rc, getErr := r.MST.Get([]byte(path))
		if getErr != nil {
			return cid.Undef, getErr
		}
		if rc == nil {
			return cid.Undef, fmt.Errorf("record not found: %s", path)
		}
		recordCid = rc

		// read the commit block
		commitBlk, err := dbs.Get(ctx, commitCid)
		if err != nil {
			return cid.Undef, fmt.Errorf("reading commit block for proof: %w", err)
		}
		proofBlocks = append(proofBlocks, commitBlk)

		// read the MST nodes on the path
		for _, nc := range nodeCIDs {
			blk, err := dbs.Get(ctx, nc)
			if err != nil {
				return cid.Undef, fmt.Errorf("reading MST node for proof: %w", err)
			}
			proofBlocks = append(proofBlocks, blk)
		}

		// read the record block
		recordBlk, err := dbs.Get(ctx, *recordCid)
		if err != nil {
			return cid.Undef, fmt.Errorf("reading record block for proof: %w", err)
		}
		proofBlocks = append(proofBlocks, recordBlk)

		// read-only, return same root
		return commitCid, nil
	}); err != nil {
		return cid.Undef, nil, err
	}

	return commitCid, proofBlocks, nil
}

func collectPathNodeCIDs(n *mst.Node, key []byte) []cid.Cid {
	if n == nil {
		return nil
	}

	var cids []cid.Cid
	if n.CID != nil {
		cids = append(cids, *n.CID)
	}

	height := mst.HeightForKey(key)
	if height >= n.Height {
		// key is at or above this level, no need to descend
		return cids
	}

	// find the child node that covers this key
	childIdx := -1
	for i, e := range n.Entries {
		if e.IsChild() {
			childIdx = i
			continue
		}
		if e.IsValue() {
			if bytes.Compare(key, e.Key) <= 0 {
				break
			}
			childIdx = -1
		}
	}

	if childIdx >= 0 && n.Entries[childIdx].Child != nil {
		cids = append(cids, collectPathNodeCIDs(n.Entries[childIdx].Child, key)...)
	}

	return cids
}

func (rm *RepoMan) incrementBlobRefs(ctx context.Context, urepo models.Repo, cbor []byte) ([]cid.Cid, error) {
	cids, err := getBlobCidsFromCbor(cbor)
	if err != nil {
		return nil, err
	}

	for _, c := range cids {
		if err := rm.db.Exec(ctx, "UPDATE blobs SET ref_count = ref_count + 1 WHERE did = ? AND cid = ?", nil, urepo.Did, c.Bytes()).Error; err != nil {
			return nil, err
		}
	}

	return cids, nil
}

func (rm *RepoMan) decrementBlobRefs(ctx context.Context, urepo models.Repo, cbor []byte) ([]cid.Cid, error) {
	cids, err := getBlobCidsFromCbor(cbor)
	if err != nil {
		return nil, err
	}

	for _, c := range cids {
		var res struct {
			ID    uint
			Count int
		}
		if err := rm.db.Raw(ctx, "UPDATE blobs SET ref_count = ref_count - 1 WHERE did = ? AND cid = ? RETURNING id, ref_count", nil, urepo.Did, c.Bytes()).Scan(&res).Error; err != nil {
			return nil, err
		}

		if res.Count == 0 {
			if err := rm.db.Exec(ctx, "DELETE FROM blobs WHERE id = ?", nil, res.ID).Error; err != nil {
				return nil, err
			}
			if err := rm.db.Exec(ctx, "DELETE FROM blob_parts WHERE blob_id = ?", nil, res.ID).Error; err != nil {
				return nil, err
			}

			// Unpin the blob from the local Kubo node so it can be
			// garbage-collected. This is best-effort — a failure here does
			// not affect the ATProto operation.
			if rm.s.ipfsConfig != nil && rm.s.ipfsConfig.NodeURL != "" {
				go rm.s.unpinFromIPFS(c.String())
			}
		}
	}

	return cids, nil
}

// to be honest, we could just store both the cbor and non-cbor in []entries above to avoid an additional
// unmarshal here. this will work for now though
func getBlobCidsFromCbor(cbor []byte) ([]cid.Cid, error) {
	var cids []cid.Cid

	decoded, err := atdata.UnmarshalCBOR(cbor)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling cbor: %w", err)
	}

	var deepiter func(any) error
	deepiter = func(item any) error {
		switch val := item.(type) {
		case map[string]any:
			if val["$type"] == "blob" {
				if ref, ok := val["ref"].(string); ok {
					c, err := cid.Parse(ref)
					if err != nil {
						return err
					}
					cids = append(cids, c)
				}
				for _, v := range val {
					return deepiter(v)
				}
			}
		case []any:
			for _, v := range val {
				if err := deepiter(v); err != nil {
					return err
				}
			}
		}

		return nil
	}

	if err := deepiter(decoded); err != nil {
		return nil, err
	}

	return cids, nil
}
