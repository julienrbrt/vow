package server

import (
	"bytes"
	"net/http"

	"github.com/bluesky-social/indigo/carstore"
	"pkg.rbrt.fr/vow/internal/helpers"
	"pkg.rbrt.fr/vow/models"
	"github.com/ipfs/go-cid"
	cbor "github.com/ipfs/go-ipld-cbor"
	"github.com/ipld/go-car"
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

	var blocks []models.Block
	if err := s.db.Raw(ctx, "SELECT * FROM blocks WHERE did = ? ORDER BY rev ASC", nil, urepo.Repo.Did).Scan(&blocks).Error; err != nil {
		logger.Error("error getting blocks", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	for _, block := range blocks {
		if _, err := carstore.LdWrite(buf, block.Cid, block.Value); err != nil {
			logger.Error("error writing block to car", "error", err)
			helpers.ServerError(w, nil)
			return
		}
	}

	w.Header().Set("Content-Type", "application/vnd.ipld.car")
	w.WriteHeader(http.StatusOK)
	w.Write(buf.Bytes())
}
