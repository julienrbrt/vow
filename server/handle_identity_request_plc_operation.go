package server

import (
	"fmt"
	"net/http"
	"time"

	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
)

func (s *Server) handleIdentityRequestPlcOperationSignature(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := s.logger.With("name", "handleIdentityRequestPlcOperationSignature")

	urepo, _ := getContextValue[*models.RepoActor](r, contextKeyRepo)

	code := fmt.Sprintf("%s-%s", helpers.RandomVarchar(5), helpers.RandomVarchar(5))
	eat := time.Now().Add(10 * time.Minute).UTC()

	if err := s.db.Exec(ctx, "UPDATE repos SET plc_operation_code = ?, plc_operation_code_expires_at = ? WHERE did = ?", nil, code, eat, urepo.Repo.Did).Error; err != nil {
		logger.Error("error updating user", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	if err := s.sendPlcTokenReset(urepo.Email, urepo.Handle, code); err != nil {
		logger.Error("error sending mail", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	w.WriteHeader(http.StatusOK)
}
