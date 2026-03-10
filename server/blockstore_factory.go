package server

import (
	vowblockstore "pkg.rbrt.fr/vow/blockstore"
)

// newBlockstoreForRepo returns an IPFS-backed blockstore for the given DID.
// All repo blocks are stored on and retrieved from the co-located Kubo node.
func newBlockstoreForRepo(did string, ipfsCfg *IPFSConfig) *vowblockstore.IPFSBlockstore {
	return vowblockstore.NewIPFS(did, ipfsCfg.NodeURL, nil)
}

// newRecordingBlockstoreForRepo wraps the IPFS blockstore in a
// RecordingBlockstore so that all reads and writes during a commit are tracked
// for firehose CAR slice construction.
func newRecordingBlockstoreForRepo(did string, ipfsCfg *IPFSConfig) (*vowblockstore.RecordingBlockstore, *vowblockstore.IPFSBlockstore) {
	base := newBlockstoreForRepo(did, ipfsCfg)
	return vowblockstore.NewRecording(base), base
}
