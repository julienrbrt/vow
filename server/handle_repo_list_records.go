package server

import (
	"net/http"
	"strconv"

	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"pkg.rbrt.fr/vow/internal/helpers"
	"pkg.rbrt.fr/vow/models"
)

type ComAtprotoRepoListRecordsRequest struct {
	Repo       string `query:"repo" validate:"required"`
	Collection string `query:"collection" validate:"required,atproto-nsid"`
	Limit      int64  `query:"limit"`
	Cursor     string `query:"cursor"`
	Reverse    bool   `query:"reverse"`
}

type ComAtprotoRepoListRecordsResponse struct {
	Cursor  *string                               `json:"cursor,omitempty"`
	Records []ComAtprotoRepoListRecordsRecordItem `json:"records"`
}

type ComAtprotoRepoListRecordsRecordItem struct {
	Uri   string         `json:"uri"`
	Cid   string         `json:"cid"`
	Value map[string]any `json:"value"`
}

func getLimitFromRequest(r *http.Request, def int) (int, error) {
	limit := def
	limitstr := r.URL.Query().Get("limit")

	if limitstr != "" {
		l64, err := strconv.ParseInt(limitstr, 10, 32)
		if err != nil {
			return 0, err
		}
		limit = int(l64)
	}

	return limit, nil
}

func (s *Server) handleListRecords(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := s.logger.With("name", "handleListRecords")

	req := ComAtprotoRepoListRecordsRequest{
		Repo:       r.URL.Query().Get("repo"),
		Collection: r.URL.Query().Get("collection"),
		Cursor:     r.URL.Query().Get("cursor"),
	}
	if v := r.URL.Query().Get("reverse"); v == "true" {
		req.Reverse = true
	}

	if err := s.validator.Struct(req); err != nil {
		helpers.InputError(w, nil)
		return
	}

	limit, err := getLimitFromRequest(r, 50)
	if err != nil {
		helpers.InputError(w, nil)
		return
	}
	if limit <= 0 {
		limit = 50
	} else if limit > 100 {
		limit = 100
	}

	sort := "DESC"
	dir := "<"
	cursorquery := ""

	if req.Reverse {
		sort = "ASC"
		dir = ">"
	}

	did := req.Repo
	if _, err := syntax.ParseDID(did); err != nil {
		actor, err := s.getActorByHandle(ctx, req.Repo)
		if err != nil {
			helpers.InputError(w, new("RepoNotFound"))
			return
		}
		did = actor.Did
	}

	params := []any{did, req.Collection}
	if req.Cursor != "" {
		params = append(params, req.Cursor)
		cursorquery = "AND created_at " + dir + " ?"
	}
	params = append(params, limit)

	var records []models.Record
	if err := s.db.Raw(ctx, "SELECT * FROM records WHERE did = ? AND nsid = ? "+cursorquery+" ORDER BY created_at "+sort+" limit ?", nil, params...).Scan(&records).Error; err != nil {
		logger.Error("error getting records", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	items := []ComAtprotoRepoListRecordsRecordItem{}
	for _, rec := range records {
		val, err := atdata.UnmarshalCBOR(rec.Value)
		if err != nil {
			helpers.ServerError(w, nil)
			return
		}

		items = append(items, ComAtprotoRepoListRecordsRecordItem{
			Uri:   "at://" + rec.Did + "/" + rec.Nsid + "/" + rec.Rkey,
			Cid:   rec.Cid,
			Value: val,
		})
	}

	var newcursor *string
	if len(records) == limit {
		newcursor = new(records[len(records)-1].CreatedAt)
	}

	s.writeJSON(w, 200, ComAtprotoRepoListRecordsResponse{
		Cursor:  newcursor,
		Records: items,
	})
}
