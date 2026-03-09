package server

import (
	"net/http"

	"pkg.rbrt.fr/vow/models"
	"github.com/ipfs/go-cid"
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

// TODO: paginate this bitch
func (s *Server) handleListRepos(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var repos []models.Repo
	if err := s.db.Raw(ctx, "SELECT * FROM repos ORDER BY created_at DESC LIMIT 500", nil).Scan(&repos).Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	items := make([]ComAtprotoSyncListReposRepoItem, 0, len(repos))
	for _, repo := range repos {
		c, err := cid.Cast(repo.Root)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
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
		Cursor: nil,
		Repos:  items,
	})
}
