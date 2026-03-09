package server

import (
	"net/http"
	"strconv"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/ipfs/go-cid"
)

type ComAtprotoSyncListBlobsResponse struct {
	Cursor *string  `json:"cursor,omitempty"`
	Cids   []string `json:"cids"`
}

func (s *Server) handleSyncListBlobs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := s.logger.With("name", "handleSyncListBlobs")

	did := r.URL.Query().Get("did")
	if did == "" {
		helpers.InputError(w, nil)
		return
	}

	// TODO: add tid param
	cursor := r.URL.Query().Get("cursor")

	limit := 50
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 1000 {
			limit = l
		}
	}

	cursorquery := ""

	params := []any{did}
	if cursor != "" {
		params = append(params, cursor)
		cursorquery = "AND created_at < ?"
	}
	params = append(params, limit)

	urepo, err := s.getRepoActorByDid(ctx, did)
	if err != nil {
		logger.Error("could not find user for requested blobs", "error", err)
		helpers.InputError(w, nil)
		return
	}

	status := urepo.Status()
	if status != nil {
		if *status == "deactivated" {
			helpers.InputError(w, to.StringPtr("RepoDeactivated"))
			return
		}
	}

	var blobs []models.Blob
	if err := s.db.Raw(ctx, "SELECT * FROM blobs WHERE did = ? "+cursorquery+" ORDER BY created_at DESC LIMIT ?", nil, params...).Scan(&blobs).Error; err != nil {
		logger.Error("error getting records", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	cstrs := make([]string, 0, len(blobs))
	for _, b := range blobs {
		if len(b.Cid) == 0 {
			logger.Error("empty cid found", "blob", b)
			continue
		}
		c, err := cid.Cast(b.Cid)
		if err != nil {
			logger.Error("error casting cid", "error", err)
			continue
		}
		cstrs = append(cstrs, c.String())
	}

	var newcursor *string
	if len(blobs) == limit {
		newcursor = &blobs[len(blobs)-1].CreatedAt
	}

	s.writeJSON(w, http.StatusOK, ComAtprotoSyncListBlobsResponse{
		Cursor: newcursor,
		Cids:   cstrs,
	})
}
