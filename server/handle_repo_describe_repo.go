package server

import (
	"net/http"
	"strings"

	"github.com/Azure/go-autorest/autorest/to"
	"gorm.io/gorm"
	"pkg.rbrt.fr/vow/identity"
	"pkg.rbrt.fr/vow/internal/helpers"
	"pkg.rbrt.fr/vow/models"
)

type ComAtprotoRepoDescribeRepoResponse struct {
	Did             string          `json:"did"`
	Handle          string          `json:"handle"`
	DidDoc          identity.DidDoc `json:"didDoc"`
	Collections     []string        `json:"collections"`
	HandleIsCorrect bool            `json:"handleIsCorrect"`
}

func (s *Server) handleDescribeRepo(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := s.logger.With("name", "handleDescribeRepo")

	did := r.URL.Query().Get("repo")
	repo, err := s.getRepoActorByDid(ctx, did)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			helpers.InputError(w, to.StringPtr("RepoNotFound"))
			return
		}

		logger.Error("error looking up repo", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	handleIsCorrect := true

	diddoc, err := s.passport.FetchDoc(r.Context(), repo.Repo.Did)
	if err != nil {
		logger.Error("error fetching diddoc", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	dochandle := ""
	for _, aka := range diddoc.AlsoKnownAs {
		if after, ok := strings.CutPrefix(aka, "at://"); ok {
			dochandle = after
			break
		}
	}

	if repo.Handle != dochandle {
		handleIsCorrect = false
	}

	if handleIsCorrect {
		resolvedDid, err := s.passport.ResolveHandle(r.Context(), repo.Handle)
		if err != nil {
			logger.Error("error resolving handle", "error", err)
			helpers.ServerError(w, nil)
			return
		}

		if resolvedDid != repo.Repo.Did {
			handleIsCorrect = false
		}
	}

	var records []models.Record
	if err := s.db.Raw(ctx, "SELECT DISTINCT(nsid) FROM records WHERE did = ?", nil, repo.Repo.Did).Scan(&records).Error; err != nil {
		logger.Error("error getting collections", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	collections := make([]string, 0, len(records))
	for _, rec := range records {
		collections = append(collections, rec.Nsid)
	}

	s.writeJSON(w, 200, ComAtprotoRepoDescribeRepoResponse{
		Did:             repo.Repo.Did,
		Handle:          repo.Handle,
		DidDoc:          *diddoc,
		Collections:     collections,
		HandleIsCorrect: handleIsCorrect,
	})
}
