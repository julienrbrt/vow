package server

import (
	"net/http"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"pkg.rbrt.fr/vow/internal/helpers"
	"pkg.rbrt.fr/vow/models"
)

// PendingWriteOp is a human-readable summary of a single operation inside a
// signing request, sent to the signer so the user knows what they are
// approving before the passkey prompt appears.
type PendingWriteOp struct {
	Type       string `json:"type"`
	Collection string `json:"collection"`
	Rkey       string `json:"rkey,omitempty"`
}

// ComAtprotoServerGetSigningKeyResponse is returned by the signing key info
// endpoint so the client can verify which public key is active and confirm the
// account is set up for BYOK signing.
type ComAtprotoServerGetSigningKeyResponse struct {
	Did       string `json:"did"`
	PublicKey string `json:"publicKey"`
}

// handleGetSigningKey returns the compressed P-256 public key registered
// for the authenticated account, encoded as a did:key string.
//
// The private key is never held by the PDS; this endpoint only confirms that a
// public key has been registered and shows what it is.
func (s *Server) handleGetSigningKey(w http.ResponseWriter, r *http.Request) {
	logger := s.logger.With("name", "handleGetSigningKey")

	repo, ok := getContextValue[*models.RepoActor](r, contextKeyRepo)
	if !ok {
		helpers.UnauthorizedError(w, nil)
		return
	}

	if len(repo.PublicKey) == 0 {
		helpers.InputError(w, new("no signing key registered for this account"))
		return
	}

	pubKey, err := atcrypto.ParsePublicBytesP256(repo.PublicKey)
	if err != nil {
		logger.Error("error parsing stored public key", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	s.writeJSON(w, 200, ComAtprotoServerGetSigningKeyResponse{
		Did:       repo.Repo.Did,
		PublicKey: pubKey.DIDKey(),
	})
}
