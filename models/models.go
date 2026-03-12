package models

import (
	"time"
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
	// AuthPublicKey holds the compressed P-256 public key bytes for WebAuthn assertion verification.
	AuthPublicKey []byte
	// SigningPublicKey holds the compressed P-256 public key bytes for commit signature verification.
	SigningPublicKey []byte
	// CredentialID is the WebAuthn credential ID returned by the authenticator
	// during registration. It is stored so the server can build the
	// allowCredentials list when requesting an assertion from the passkey.
	CredentialID []byte
	Rev          string
	Root         []byte
	Preferences  []byte
	Deactivated  bool
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
