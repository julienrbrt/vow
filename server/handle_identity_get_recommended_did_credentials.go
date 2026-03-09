package server

import (
	"net/http"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"pkg.rbrt.fr/vow/internal/helpers"
	"pkg.rbrt.fr/vow/models"
)

func (s *Server) handleGetRecommendedDidCredentials(w http.ResponseWriter, r *http.Request) {
	logger := s.logger.With("name", "handleIdentityGetRecommendedDidCredentials")

	repo, _ := getContextValue[*models.RepoActor](r, contextKeyRepo)
	k, err := atcrypto.ParsePrivateBytesK256(repo.SigningKey)
	if err != nil {
		logger.Error("error parsing key", "error", err)
		helpers.ServerError(w, nil)
		return
	}
	creds, err := s.plcClient.CreateDidCredentials(k, "", repo.Actor.Handle)
	if err != nil {
		logger.Error("error creating did credentials", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	s.writeJSON(w, 200, creds)
}
