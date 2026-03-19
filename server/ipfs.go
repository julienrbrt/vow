package server

import (
	"context"

	"github.com/ipfs/boxo/path"
	"github.com/ipfs/go-cid"
	caopts "github.com/ipfs/kubo/core/coreiface/options"
)

// unpinFromIPFS asks the local Kubo node to remove the recursive pin for the
// given CID so the content becomes eligible for garbage collection.
// It is intentionally best-effort: errors are logged but not propagated.
func (s *Server) unpinFromIPFS(cidStr string) {
	c, err := cid.Decode(cidStr)
	if err != nil {
		s.logger.Warn("ipfs unpin: failed to decode CID", "cid", cidStr, "error", err)
		return
	}

	p := path.FromCid(c)
	if err := s.ipfsAPI.Pin().Rm(context.Background(), p, caopts.Pin.RmRecursive(true)); err != nil {
		// Don't log loudly if CID was never pinned
		if !isNotPinnedError(err) {
			s.logger.Warn("ipfs unpin: failed to unpin", "cid", cidStr, "error", err)
		}
		return
	}

	s.logger.Info("ipfs unpin: blob unpinned", "cid", cidStr)
}

func isNotPinnedError(err error) bool {
	return err != nil && (err.Error() == "not pinned" || err.Error() == "is not pinned")
}
