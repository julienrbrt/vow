package server

import (
	"net/http"

	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/haileyok/cocoon/models"
)

type ComAtprotoRepoGetRecordResponse struct {
	Uri   string         `json:"uri"`
	Cid   string         `json:"cid"`
	Value map[string]any `json:"value"`
}

func (s *Server) handleRepoGetRecord(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	repo := r.URL.Query().Get("repo")
	collection := r.URL.Query().Get("collection")
	rkey := r.URL.Query().Get("rkey")
	cidstr := r.URL.Query().Get("cid")

	params := []any{repo, collection, rkey}
	cidquery := ""

	if cidstr != "" {
		c, err := syntax.ParseCID(cidstr)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		params = append(params, c.String())
		cidquery = " AND cid = ?"
	}

	var record models.Record
	if err := s.db.Raw(ctx, "SELECT * FROM records WHERE did = ? AND nsid = ? AND rkey = ?"+cidquery, nil, params...).Scan(&record).Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	val, err := atdata.UnmarshalCBOR(record.Value)
	if err != nil {
		// Fall back to proxy if we can't find/decode the record locally
		s.handleProxy(w, r)
		return
	}

	s.writeJSON(w, 200, ComAtprotoRepoGetRecordResponse{
		Uri:   "at://" + record.Did + "/" + record.Nsid + "/" + record.Rkey,
		Cid:   record.Cid,
		Value: val,
	})
}
