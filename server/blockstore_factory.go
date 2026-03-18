package server

import (
	"github.com/ipfs/kubo/client/rpc"
	vowblockstore "pkg.rbrt.fr/vow/blockstore"
)

// newBlockstoreForRepo returns the blockstore for a DID.
func newBlockstoreForRepo(did string, ipfsAPI *rpc.HttpApi) *vowblockstore.IPFSBlockstore {
	return vowblockstore.NewIPFS(did, ipfsAPI)
}

// newRecordingBlockstoreForRepo adds read/write logging.
func newRecordingBlockstoreForRepo(did string, ipfsAPI *rpc.HttpApi) (*vowblockstore.RecordingBlockstore, *vowblockstore.IPFSBlockstore) {
	base := newBlockstoreForRepo(did, ipfsAPI)
	return vowblockstore.NewRecording(base), base
}
