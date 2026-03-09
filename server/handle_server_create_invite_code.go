package server

import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
)

type ComAtprotoServerCreateInviteCodeRequest struct {
	UseCount   int     `json:"useCount" validate:"required"`
	ForAccount *string `json:"forAccount,omitempty"`
}

type ComAtprotoServerCreateInviteCodeResponse struct {
	Code string `json:"code"`
}

func (s *Server) handleCreateInviteCode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := s.logger.With("name", "handleServerCreateInviteCode")

	var req ComAtprotoServerCreateInviteCodeRequest
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

	ic := uuid.NewString()

	var acc string
	if req.ForAccount == nil {
		acc = "admin"
	} else {
		acc = *req.ForAccount
	}

	if err := s.db.Create(ctx, &models.InviteCode{
		Code:              ic,
		Did:               acc,
		RemainingUseCount: req.UseCount,
	}, nil).Error; err != nil {
		logger.Error("error creating invite code", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	s.writeJSON(w, 200, ComAtprotoServerCreateInviteCodeResponse{
		Code: ic,
	})
}
