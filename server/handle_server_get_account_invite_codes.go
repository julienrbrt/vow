package server

import (
	"net/http"
	"time"

	"pkg.rbrt.fr/vow/internal/helpers"
	"pkg.rbrt.fr/vow/models"
)

type ComAtprotoServerGetAccountInviteCodesResponse struct {
	Codes []InviteCodeView `json:"codes"`
}

type InviteCodeView struct {
	Code       string              `json:"code"`
	Available  int                 `json:"available"`
	Disabled   bool                `json:"disabled"`
	ForAccount string              `json:"forAccount"`
	CreatedBy  string              `json:"createdBy"`
	CreatedAt  string              `json:"createdAt"`
	Uses       []InviteCodeUseView `json:"uses"`
}

type InviteCodeUseView struct {
	UsedBy string `json:"usedBy"`
	UsedAt string `json:"usedAt"`
}

func (s *Server) handleGetAccountInviteCodes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := s.logger.With("name", "handleGetAccountInviteCodes")

	repo, ok := getContextValue[*models.RepoActor](r, contextKeyRepo)
	if !ok {
		helpers.UnauthorizedError(w, nil)
		return
	}

	did := repo.Repo.Did

	includeUsed := r.URL.Query().Get("includeUsed") != "false"

	var codes []models.InviteCode
	if err := s.db.Raw(ctx, "SELECT * FROM invite_codes WHERE did = ?", nil, did).Scan(&codes).Error; err != nil {
		logger.Error("error fetching invite codes", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	result := make([]InviteCodeView, 0, len(codes))
	for _, code := range codes {
		if code.Code == "" {
			continue
		}

		var uses []models.InviteCodeUse
		if err := s.db.Raw(ctx, "SELECT * FROM invite_code_uses WHERE code = ?", nil, code.Code).Scan(&uses).Error; err != nil {
			logger.Error("error fetching invite code uses", "error", err)
			helpers.ServerError(w, nil)
			return
		}

		if !includeUsed && len(uses) > 0 && code.RemainingUseCount <= 0 {
			continue
		}

		useViews := make([]InviteCodeUseView, 0, len(uses))
		for _, u := range uses {
			if u.UsedBy == "" {
				continue
			}
			useViews = append(useViews, InviteCodeUseView{
				UsedBy: u.UsedBy,
				UsedAt: u.UsedAt.Format(time.RFC3339),
			})
		}

		createdAt := code.CreatedAt
		if createdAt.IsZero() {
			createdAt = time.Now()
		}

		result = append(result, InviteCodeView{
			Code:       code.Code,
			Available:  code.RemainingUseCount,
			Disabled:   code.Disabled,
			ForAccount: did,
			CreatedBy:  did,
			CreatedAt:  createdAt.Format(time.RFC3339),
			Uses:       useViews,
		})
	}

	s.writeJSON(w, 200, ComAtprotoServerGetAccountInviteCodesResponse{
		Codes: result,
	})
}
