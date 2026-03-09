package server

import (
	"net/http"
	"strconv"

	"github.com/ipfs/go-cid"
	"pkg.rbrt.fr/vow/internal/helpers"
	"pkg.rbrt.fr/vow/models"
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
		// cursor is the CID string of the last blob on the previous page;
		// convert to bytes for the comparison against the binary cid column.
		cursorCid, err := cid.Decode(cursor)
		if err != nil {
			helpers.InputError(w, new("invalid cursor"))
			return
		}
		params = append(params, cursorCid.Bytes())
		cursorquery = "AND cid > ?"
	}
	params = append(params, limit+1)

	urepo, err := s.getRepoActorByDid(ctx, did)
	if err != nil {
		logger.Error("could not find user for requested blobs", "error", err)
		helpers.InputError(w, nil)
		return
	}

	status := urepo.Status()
	if status != nil {
		if *status == "deactivated" {
			helpers.InputError(w, new("RepoDeactivated"))
			return
		}
	}

	var blobs []models.Blob
	if err := s.db.Raw(ctx, "SELECT * FROM blobs WHERE did = ? "+cursorquery+" ORDER BY cid ASC LIMIT ?", nil, params...).Scan(&blobs).Error; err != nil {
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
	if len(blobs) > limit {
		blobs = blobs[:limit]
		lastCid, err := cid.Cast(blobs[len(blobs)-1].Cid)
		if err == nil {
			s := lastCid.String()
			newcursor = &s
		}
	}

	s.writeJSON(w, http.StatusOK, ComAtprotoSyncListBlobsResponse{
		Cursor: newcursor,
		Cids:   cstrs,
	})
}
