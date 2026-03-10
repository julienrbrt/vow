package server

import (
	"encoding/json"
	"net/http"

	"pkg.rbrt.fr/vow/internal/helpers"
	"pkg.rbrt.fr/vow/models"
)

type ComAtprotoRepoApplyWritesInput struct {
	Repo       string                          `json:"repo" validate:"required,atproto-did"`
	Validate   *bool                           `json:"bool,omitempty"`
	Writes     []ComAtprotoRepoApplyWritesItem `json:"writes"`
	SwapCommit *string                         `json:"swapCommit"`
}

type ComAtprotoRepoApplyWritesItem struct {
	Type       string          `json:"$type"`
	Collection string          `json:"collection"`
	Rkey       string          `json:"rkey"`
	Value      *MarshalableMap `json:"value,omitempty"`
}

type ComAtprotoRepoApplyWritesOutput struct {
	Commit  RepoCommit         `json:"commit"`
	Results []ApplyWriteResult `json:"results"`
}

func (s *Server) handleApplyWrites(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := s.logger.With("name", "handleRepoApplyWrites")

	var req ComAtprotoRepoApplyWritesInput
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Error("error binding", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	if err := s.validator.Struct(req); err != nil {
		logger.Error("error validating", "error", err)
		helpers.InputError(w, nil)
		return
	}

	repo, _ := getContextValue[*models.RepoActor](r, contextKeyRepo)

	if repo.Repo.Did != req.Repo {
		logger.Warn("mismatched repo/auth")
		helpers.InputError(w, nil)
		return
	}

	ops := make([]Op, 0, len(req.Writes))
	for _, item := range req.Writes {
		ops = append(ops, Op{
			Type:       OpType(item.Type),
			Collection: item.Collection,
			Rkey:       &item.Rkey,
			Record:     item.Value,
		})
	}

	results, err := s.repoman.applyWrites(ctx, repo.Repo, ops, req.SwapCommit)
	if err != nil {
		logger.Error("error applying writes", "error", err)
		helpers.HandleSignerError(w, err)
		return
	}

	commit := *results[0].Commit

	for i := range results {
		results[i].Commit = nil
	}

	s.writeJSON(w, http.StatusOK, ComAtprotoRepoApplyWritesOutput{
		Commit:  commit,
		Results: results,
	})
}
