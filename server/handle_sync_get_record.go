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

func (s *Server) handleSyncGetRecord(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := s.logger.With("name", "handleSyncGetRecord")

	did := r.URL.Query().Get("did")
	collection := r.URL.Query().Get("collection")
	rkey := r.URL.Query().Get("rkey")

	var urepo models.Repo
	if err := s.db.Raw(ctx, "SELECT * FROM repos WHERE did = ?", nil, did).Scan(&urepo).Error; err != nil {
		logger.Error("error getting repo", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	root, blocks, err := s.repoman.getRecordProof(ctx, urepo, collection, rkey)
	if err != nil {
		logger.Error("error getting record proof", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	buf := new(bytes.Buffer)

	hb, err := cbor.DumpObject(&car.CarHeader{
		Roots:   []cid.Cid{root},
		Version: 1,
	})
	if err != nil {
		logger.Error("error dumping car header", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	if _, err := carstore.LdWrite(buf, hb); err != nil {
		logger.Error("error writing to car", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	for _, blk := range blocks {
		if _, err := carstore.LdWrite(buf, blk.Cid().Bytes(), blk.RawData()); err != nil {
			logger.Error("error writing block to car", "error", err)
			helpers.ServerError(w, nil)
			return
		}
	}

	w.Header().Set("Content-Type", "application/vnd.ipld.car")
	w.WriteHeader(http.StatusOK)
	w.Write(buf.Bytes())
}
