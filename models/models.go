package models

import (
	"time"

	gethcrypto "github.com/ethereum/go-ethereum/crypto"
)

type Repo struct {
	Did                            string `gorm:"primaryKey"`
	CreatedAt                      time.Time
	Email                          string `gorm:"uniqueIndex"`
	EmailConfirmedAt               *time.Time
	EmailVerificationCode          *string
	EmailVerificationCodeExpiresAt *time.Time
	EmailUpdateCode                *string
	EmailUpdateCodeExpiresAt       *time.Time
	PasswordResetCode              *string
	PasswordResetCodeExpiresAt     *time.Time
	PlcOperationCode               *string
	PlcOperationCodeExpiresAt      *time.Time
	AccountDeleteCode              *string
	AccountDeleteCodeExpiresAt     *time.Time
	Password                       string
	// PublicKey holds the compressed secp256k1 public key bytes for the
	// account. This is the only key material the PDS retains.
	PublicKey   []byte
	Rev         string
	Root        []byte
	Preferences []byte
	Deactivated bool
	// X402PinningEnabled controls whether blobs and repo blocks are
	// additionally pinned to a remote x402-gated pinning service after being
	// written to the local Kubo node. When false (the default) content lives
	// only on the co-located node.
	X402PinningEnabled bool `gorm:"default:false"`
}

// EthereumAddress derives the EIP-55 checksummed Ethereum address from the
// stored compressed secp256k1 public key. Returns an empty string if no
// public key has been registered yet.
//
// The derivation is: decompress pubkey → keccak256(pubkey[1:]) → take last 20 bytes.
// This is the same address the user's Ethereum wallet (Rabby, MetaMask, etc.)
// will present, so it can be passed as the "from" field in EIP-3009 payment
// authorisations without any separate storage.
func (r *Repo) EthereumAddress() string {
	if len(r.PublicKey) == 0 {
		return ""
	}
	ecPub, err := gethcrypto.DecompressPubkey(r.PublicKey)
	if err != nil {
		return ""
	}
	return gethcrypto.PubkeyToAddress(*ecPub).Hex()
}

func (r *Repo) Status() *string {
	var status *string
	if r.Deactivated {
		status = new("deactivated")
	}
	return status
}

func (r *Repo) Active() bool {
	return r.Status() == nil
}

type Actor struct {
	Did    string `gorm:"primaryKey"`
	Handle string `gorm:"uniqueIndex"`
}

type RepoActor struct {
	Repo
	Actor
}

type InviteCode struct {
	Code              string `gorm:"primaryKey"`
	Did               string `gorm:"index"`
	RemainingUseCount int
	CreatedAt         time.Time
	Disabled          bool `gorm:"default:false"`
}

type InviteCodeUse struct {
	ID     uint   `gorm:"primaryKey"`
	Code   string `gorm:"index"`
	UsedBy string
	UsedAt time.Time
}

// PendingWrite represents a write (or PLC operation) that has been prepared by
// the PDS and is waiting for the user's client to sign it. Once the signature
// is submitted via handleSubmitSignature the stored CommitData is used to
// finalise the commit without the PDS ever having held the private key.
type PendingWrite struct {
	ID          string `gorm:"primaryKey"`
	Did         string `gorm:"index"`
	PayloadHash string
	// Payload is the canonical bytes that the client must sign.
	Payload []byte
	// Data holds the original serialised write request so it can be replayed
	// after signature verification.
	Data []byte
	// CommitData holds a JSON-serialised pendingCommitState that contains
	// everything needed to finalise the commit once the signature arrives:
	// the unsigned commit CBOR, MST diff blocks, record entries, firehose ops,
	// and per-op results. It is nil for PLC-operation pending writes.
	CommitData []byte
	CreatedAt  time.Time
	ExpiresAt  time.Time `gorm:"index"`
}

type Token struct {
	Token        string `gorm:"primaryKey"`
	Did          string `gorm:"index"`
	RefreshToken string `gorm:"index"`
	CreatedAt    time.Time
	ExpiresAt    time.Time `gorm:"index:,sort:asc"`
}

type RefreshToken struct {
	Token     string `gorm:"primaryKey"`
	Did       string `gorm:"index"`
	CreatedAt time.Time
	ExpiresAt time.Time `gorm:"index:,sort:asc"`
}

type Record struct {
	Did       string `gorm:"primaryKey:idx_record_did_created_at;index:idx_record_did_nsid"`
	CreatedAt string `gorm:"index;index:idx_record_did_created_at,sort:desc"`
	Nsid      string `gorm:"primaryKey;index:idx_record_did_nsid"`
	Rkey      string `gorm:"primaryKey"`
	Cid       string
	Value     []byte
}

// Blob is a metadata index entry for a user-uploaded blob. The actual blob
// data lives on IPFS; this row exists so we can list blobs by DID, track
// reference counts from records, and know which user owns each CID.
type Blob struct {
	ID        uint
	CreatedAt string `gorm:"index"`
	Did       string `gorm:"index;index:idx_blob_did_cid"`
	Cid       []byte `gorm:"index;index:idx_blob_did_cid"`
	RefCount  int
}

type ReservedKey struct {
	KeyDid     string  `gorm:"primaryKey"`
	Did        *string `gorm:"index"`
	PrivateKey []byte
	CreatedAt  time.Time `gorm:"index"`
}

type EventRecord struct {
	Seq       int64 `gorm:"primaryKey;autoIncrement:false"`
	CreatedAt time.Time
	Did       string `gorm:"index"`
	Type      string
	Data      []byte
}
