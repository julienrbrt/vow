package server

import (
	"fmt"
	"io"
	"maps"
	"net/http"
	"strings"

	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"pkg.rbrt.fr/vow/internal/helpers"
	"pkg.rbrt.fr/vow/models"
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
		s.proxyToAppView(w, r)
		return
	}

	s.writeJSON(w, 200, ComAtprotoRepoGetRecordResponse{
		Uri:   "at://" + record.Did + "/" + record.Nsid + "/" + record.Rkey,
		Cid:   record.Cid,
		Value: val,
	})
}

func (s *Server) proxyToAppView(w http.ResponseWriter, r *http.Request) {
	endpoint, _, err := s.getAtprotoProxyEndpointFromRequest(r)
	if err != nil {
		s.logger.Error("could not get appview endpoint", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	targetURL := fmt.Sprintf("%s%s?%s", strings.TrimSuffix(endpoint, "/"), r.URL.Path, r.URL.RawQuery)

	req, err := http.NewRequest(http.MethodGet, targetURL, nil)
	if err != nil {
		helpers.ServerError(w, nil)
		return
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		helpers.ServerError(w, nil)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	maps.Copy(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}
