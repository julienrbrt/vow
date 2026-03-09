package server

import (
	"net/http"
	"strconv"

	"github.com/ipfs/go-cid"
	"pkg.rbrt.fr/vow/internal/helpers"
	"pkg.rbrt.fr/vow/models"
)

type ComAtprotoSyncListReposResponse struct {
	Cursor *string                           `json:"cursor,omitempty"`
	Repos  []ComAtprotoSyncListReposRepoItem `json:"repos"`
}

type ComAtprotoSyncListReposRepoItem struct {
	Did    string  `json:"did"`
	Head   string  `json:"head"`
	Rev    string  `json:"rev"`
	Active bool    `json:"active"`
	Status *string `json:"status,omitempty"`
}

func (s *Server) handleListRepos(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	limit := 500
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 1000 {
			limit = l
		}
	}

	cursor := r.URL.Query().Get("cursor")

	params := []any{}
	cursorClause := ""
	if cursor != "" {
		cursorClause = "WHERE did > ?"
		params = append(params, cursor)
	}
	params = append(params, limit+1)

	var repos []models.Repo
	if err := s.db.Raw(ctx, "SELECT * FROM repos "+cursorClause+" ORDER BY did ASC LIMIT ?", nil, params...).Scan(&repos).Error; err != nil {
		helpers.ServerError(w, nil)
		return
	}

	var nextCursor *string
	if len(repos) > limit {
		repos = repos[:limit]
		nextCursor = &repos[len(repos)-1].Did
	}

	items := make([]ComAtprotoSyncListReposRepoItem, 0, len(repos))
	for _, repo := range repos {
		c, err := cid.Cast(repo.Root)
		if err != nil {
			helpers.ServerError(w, nil)
			return
		}

		items = append(items, ComAtprotoSyncListReposRepoItem{
			Did:    repo.Did,
			Head:   c.String(),
			Rev:    repo.Rev,
			Active: repo.Active(),
			Status: repo.Status(),
		})
	}

	s.writeJSON(w, 200, ComAtprotoSyncListReposResponse{
		Cursor: nextCursor,
		Repos:  items,
	})
}
