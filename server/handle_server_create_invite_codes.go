package server

import (
	"encoding/json"
	"net/http"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/google/uuid"
	"pkg.rbrt.fr/vow/internal/helpers"
	"pkg.rbrt.fr/vow/models"
)

type ComAtprotoServerCreateInviteCodesRequest struct {
	CodeCount   *int      `json:"codeCount,omitempty"`
	UseCount    int       `json:"useCount" validate:"required"`
	ForAccounts *[]string `json:"forAccounts,omitempty"`
}

type ComAtprotoServerCreateInviteCodesResponse []ComAtprotoServerCreateInviteCodesItem

type ComAtprotoServerCreateInviteCodesItem struct {
	Account string   `json:"account"`
	Codes   []string `json:"codes"`
}

func (s *Server) handleCreateInviteCodes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := s.logger.With("name", "handleServerCreateInviteCodes")

	var req ComAtprotoServerCreateInviteCodesRequest
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

	if req.CodeCount == nil {
		req.CodeCount = to.IntPtr(1)
	}

	if req.ForAccounts == nil {
		req.ForAccounts = to.StringSlicePtr([]string{"admin"})
	}

	codes := make([]ComAtprotoServerCreateInviteCodesItem, 0, len(*req.ForAccounts))

	for _, did := range *req.ForAccounts {
		ics := make([]string, 0, *req.CodeCount)

		for range *req.CodeCount {
			ic := uuid.NewString()
			ics = append(ics, ic)

			if err := s.db.Create(ctx, &models.InviteCode{
				Code:              ic,
				Did:               did,
				RemainingUseCount: req.UseCount,
			}, nil).Error; err != nil {
				logger.Error("error creating invite code", "error", err)
				helpers.ServerError(w, nil)
				return
			}
		}

		codes = append(codes, ComAtprotoServerCreateInviteCodesItem{
			Account: did,
			Codes:   ics,
		})
	}

	s.writeJSON(w, 200, codes)
}
