package server

import (
	"bytes"
	"net/http"

	"github.com/bluesky-social/indigo/carstore"
	"github.com/ipfs/go-cid"
	cbor "github.com/ipfs/go-ipld-cbor"
	"github.com/ipld/go-car"
	"pkg.rbrt.fr/vow/internal/helpers"
)

type ComAtprotoSyncGetBlocksRequest struct {
	Did  string   `query:"did"`
	Cids []string `query:"cids"`
}

func (s *Server) handleGetBlocks(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := s.logger.With("name", "handleSyncGetBlocks")

	did := r.URL.Query().Get("did")
	if did == "" {
		helpers.InputError(w, nil)
		return
	}

	cidsParam := r.URL.Query()["cids"]
	var cids []cid.Cid

	for _, cs := range cidsParam {
		c, err := cid.Cast([]byte(cs))
		if err != nil {
			logger.Error("error parsing cid", "cid", cs, "error", err)
			helpers.InputError(w, nil)
			return
		}
		cids = append(cids, c)
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

	bs := newBlockstoreForRepo(urepo.Repo.Did, s.ipfsConfig)

	for _, c := range cids {
		b, err := bs.Get(ctx, c)
		if err != nil {
			logger.Error("error getting block", "cid", c.String(), "error", err)
			helpers.ServerError(w, nil)
			return
		}

		if _, err := carstore.LdWrite(buf, b.Cid().Bytes(), b.RawData()); err != nil {
			logger.Error("error writing block to car", "error", err)
			helpers.ServerError(w, nil)
			return
		}
	}

	w.Header().Set("Content-Type", "application/vnd.ipld.car")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(buf.Bytes()); err != nil {
		logger.Error("failed to write response", "error", err)
	}
}
