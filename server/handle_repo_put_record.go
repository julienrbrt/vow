package server

import (
	"encoding/json"
	"net/http"

	"pkg.rbrt.fr/vow/internal/helpers"
	"pkg.rbrt.fr/vow/models"
)

type ComAtprotoRepoPutRecordInput struct {
	Repo       string         `json:"repo" validate:"required,atproto-did"`
	Collection string         `json:"collection" validate:"required,atproto-nsid"`
	Rkey       string         `json:"rkey" validate:"required,atproto-rkey"`
	Validate   *bool          `json:"bool,omitempty"`
	Record     MarshalableMap `json:"record" validate:"required"`
	SwapRecord *string        `json:"swapRecord"`
	SwapCommit *string        `json:"swapCommit"`
}

func (s *Server) handlePutRecord(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := s.logger.With("name", "handlePutRecord")

	repo, _ := getContextValue[*models.RepoActor](r, contextKeyRepo)

	var req ComAtprotoRepoPutRecordInput
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Error("error decoding", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	if err := s.validator.Struct(req); err != nil {
		logger.Error("error validating", "error", err)
		helpers.InputError(w, nil)
		return
	}

	if repo.Repo.Did != req.Repo {
		logger.Warn("mismatched repo/auth")
		helpers.InputError(w, nil)
		return
	}

	optype := OpTypeCreate
	if req.SwapRecord != nil {
		optype = OpTypeUpdate
	}

	results, err := s.repoman.applyWrites(ctx, repo.Repo, []Op{
		{
			Type:       optype,
			Collection: req.Collection,
			Rkey:       &req.Rkey,
			Validate:   req.Validate,
			Record:     &req.Record,
			SwapRecord: req.SwapRecord,
		},
	}, req.SwapCommit)
	if err != nil {
		logger.Error("error applying writes", "error", err)
		helpers.HandleSignerError(w, err)
		return
	}

	results[0].Type = nil

	s.writeJSON(w, 200, results[0])
}
