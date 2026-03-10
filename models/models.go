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
}

// EthereumAddress returns the Ethereum address for PublicKey.
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

type EventRecord struct {
	Seq       int64 `gorm:"primaryKey;autoIncrement:false"`
	CreatedAt time.Time
	Did       string `gorm:"index"`
	Type      string
	Data      []byte
}
