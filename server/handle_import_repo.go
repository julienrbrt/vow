package server

import (
	"bytes"
	"io"
	"net/http"
	"slices"
	"strings"

	"github.com/bluesky-social/indigo/atproto/syntax"
	blocks "github.com/ipfs/go-block-format"
	"github.com/ipfs/go-cid"
	"github.com/ipld/go-car"
	"pkg.rbrt.fr/vow/internal/helpers"
	"pkg.rbrt.fr/vow/models"
)

func (s *Server) handleRepoImportRepo(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := s.logger.With("name", "handleImportRepo")

	urepo, _ := getContextValue[*models.RepoActor](r, contextKeyRepo)

	b, err := io.ReadAll(r.Body)
	if err != nil {
		logger.Error("could not read bytes in import request", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	bs := newBlockstoreForRepo(urepo.Repo.Did, s.ipfsAPI)

	cs, err := car.NewCarReader(bytes.NewReader(b))
	if err != nil {
		logger.Error("could not read car in import request", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	orderedBlocks := []blocks.Block{}
	currBlock, err := cs.Next()
	if err != nil {
		logger.Error("could not get first block from car", "error", err)
		helpers.ServerError(w, nil)
		return
	}
	currBlockCt := 1

	for currBlock != nil {
		logger.Info("someone is importing their repo", "block", currBlockCt)
		orderedBlocks = append(orderedBlocks, currBlock)
		next, _ := cs.Next()
		currBlock = next
		currBlockCt++
	}

	slices.Reverse(orderedBlocks)

	if err := bs.PutMany(ctx, orderedBlocks); err != nil {
		logger.Error("could not insert blocks", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	atRepo, err := openRepo(ctx, bs, cs.Header.Roots[0], urepo.Repo.Did)
	if err != nil {
		logger.Error("could not open repo", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	tx := s.db.Begin(ctx)

	clock := syntax.NewTIDClock(0)

	if err := atRepo.MST.Walk(func(key []byte, recordCid cid.Cid) error {
		pts := strings.Split(string(key), "/")
		nsid := pts[0]
		rkey := pts[1]
		cidStr := recordCid.String()
		blkData, err := bs.Get(ctx, recordCid)
		if err != nil {
			logger.Error("record bytes don't exist in blockstore", "error", err)
			return err
		}

		rec := models.Record{
			Did:       urepo.Repo.Did,
			CreatedAt: clock.Next().String(),
			Nsid:      nsid,
			Rkey:      rkey,
			Cid:       cidStr,
			Value:     blkData.RawData(),
		}

		if err := tx.Save(rec).Error; err != nil {
			return err
		}

		return nil
	}); err != nil {
		tx.Rollback()
		logger.Error("error iterating repo blocks", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	tx.Commit()

	// Sign the import commit with the PDS rotation key instead of a throwaway
	// ephemeral key. The user can supply their own signing key later via the
	// account page; subsequent writes require a registered public key and a
	// connected signer.
	root, rev, err := commitRepo(ctx, bs, atRepo, s.plcClient.RotationKeyBytes())
	if err != nil {
		logger.Error("error committing", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	if err := s.UpdateRepo(ctx, urepo.Repo.Did, root, rev); err != nil {
		logger.Error("error updating repo after commit", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	w.WriteHeader(http.StatusOK)
}
