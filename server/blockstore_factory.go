package server

import (
	"net/http"

	"github.com/ipfs/kubo/client/rpc"
	vowblockstore "pkg.rbrt.fr/vow/blockstore"
)

// newBlockstoreForRepo returns the blockstore for a DID.
func newBlockstoreForRepo(did string, ipfsCfg *IPFSConfig) *vowblockstore.IPFSBlockstore {
	cli, err := rpc.NewURLApiWithClient(ipfsCfg.NodeURL, http.DefaultClient)
	if err != nil {
		panic(err)
	}
	return vowblockstore.NewIPFS(did, cli)
}

// newRecordingBlockstoreForRepo adds read/write logging.
func newRecordingBlockstoreForRepo(did string, ipfsCfg *IPFSConfig) (*vowblockstore.RecordingBlockstore, *vowblockstore.IPFSBlockstore) {
	base := newBlockstoreForRepo(did, ipfsCfg)
	return vowblockstore.NewRecording(base), base
}
