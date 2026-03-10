package server

import (
	vowblockstore "pkg.rbrt.fr/vow/blockstore"
)

// newBlockstoreForRepo returns the blockstore for a DID.
func newBlockstoreForRepo(did string, ipfsCfg *IPFSConfig) *vowblockstore.IPFSBlockstore {
	return vowblockstore.NewIPFS(did, ipfsCfg.NodeURL, nil)
}

// newRecordingBlockstoreForRepo adds read/write logging.
func newRecordingBlockstoreForRepo(did string, ipfsCfg *IPFSConfig) (*vowblockstore.RecordingBlockstore, *vowblockstore.IPFSBlockstore) {
	base := newBlockstoreForRepo(did, ipfsCfg)
	return vowblockstore.NewRecording(base), base
}
