package server

import (
	"net/http"

	"github.com/ipfs/go-cid"
	"pkg.rbrt.fr/vow/internal/helpers"
	"pkg.rbrt.fr/vow/models"
)

type ComAtprotoServerCheckAccountStatusResponse struct {
	Activated          bool   `json:"activated"`
	ValidDid           bool   `json:"validDid"`
	RepoCommit         string `json:"repoCommit"`
	RepoRev            string `json:"repoRev"`
	RepoBlocks         int64  `json:"repoBlocks"`
	IndexedRecords     int64  `json:"indexedRecords"`
	PrivateStateValues int64  `json:"privateStateValues"`
	ExpectedBlobs      int64  `json:"expectedBlobs"`
	ImportedBlobs      int64  `json:"importedBlobs"`
}

func (s *Server) handleServerCheckAccountStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := s.logger.With("name", "handleServerCheckAccountStatus")

	urepo, _ := getContextValue[*models.RepoActor](r, contextKeyRepo)

	resp := ComAtprotoServerCheckAccountStatusResponse{
		Activated: urepo.Active(),
		ValidDid:  urepo.Root != nil,
		RepoRev:   urepo.Rev,
	}

	if len(urepo.Root) > 0 {
		rootcid, err := cid.Cast(urepo.Root)
		if err != nil {
			logger.Error("error casting cid", "error", err)
			helpers.ServerError(w, nil)
			return
		}
		resp.RepoCommit = rootcid.String()
	}

	type CountResp struct {
		Ct int64
	}

	var blockCtResp CountResp
	if err := s.db.Raw(ctx, "SELECT COUNT(*) AS ct FROM blocks WHERE did = ?", nil, urepo.Repo.Did).Scan(&blockCtResp).Error; err != nil {
		logger.Error("error getting block count", "error", err)
		helpers.ServerError(w, nil)
		return
	}
	resp.RepoBlocks = blockCtResp.Ct

	var recCtResp CountResp
	if err := s.db.Raw(ctx, "SELECT COUNT(*) AS ct FROM records WHERE did = ?", nil, urepo.Repo.Did).Scan(&recCtResp).Error; err != nil {
		logger.Error("error getting record count", "error", err)
		helpers.ServerError(w, nil)
		return
	}
	resp.IndexedRecords = recCtResp.Ct

	var blobCtResp CountResp
	if err := s.db.Raw(ctx, "SELECT COUNT(*) AS ct FROM blobs WHERE did = ?", nil, urepo.Repo.Did).Scan(&blobCtResp).Error; err != nil {
		logger.Error("error getting record count", "error", err)
		helpers.ServerError(w, nil)
		return
	}
	resp.ExpectedBlobs = blobCtResp.Ct
	resp.ImportedBlobs = blobCtResp.Ct

	s.writeJSON(w, 200, resp)
}
