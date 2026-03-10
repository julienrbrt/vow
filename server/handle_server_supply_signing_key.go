package server

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"strings"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	gethcrypto "github.com/ethereum/go-ethereum/crypto"
	"pkg.rbrt.fr/vow/identity"
	"pkg.rbrt.fr/vow/internal/helpers"
	"pkg.rbrt.fr/vow/models"
	"pkg.rbrt.fr/vow/plc"
)

// ComAtprotoServerSupplySigningKeyRequest is sent by the account page to
// register the user's secp256k1 public key with the PDS. The client sends the
// wallet address and the signature over a fixed registration message; the PDS
// recovers the public key server-side using go-ethereum and verifies it
// matches the wallet address before storing it.
type ComAtprotoServerSupplySigningKeyRequest struct {
	// WalletAddress is the EIP-55 checksummed Ethereum address of the wallet.
	WalletAddress string `json:"walletAddress" validate:"required"`
	// Signature is the hex-encoded 65-byte personal_sign signature (0x-prefixed).
	Signature string `json:"signature" validate:"required"`
}

type ComAtprotoServerSupplySigningKeyResponse struct {
	Did       string `json:"did"`
	PublicKey string `json:"publicKey"` // did:key representation
}

// handleSupplySigningKey lets the account page register the user's
// secp256k1 public key. The PDS stores only the compressed public key bytes
// and updates the PLC DID document so the key becomes the active
// verificationMethods.atproto entry.
//
// The private key is never transmitted to or stored by the PDS.
// registrationMessage is the fixed plaintext that the wallet must sign during
// key registration. It is prefixed with the Ethereum personal_sign envelope
// ("\x19Ethereum Signed Message:\n<len>") by the wallet before signing.
const registrationMessage = "Vow key registration"

func (s *Server) handleSupplySigningKey(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := s.logger.With("name", "handleSupplySigningKey")

	repo, ok := getContextValue[*models.RepoActor](r, contextKeyRepo)
	if !ok {
		helpers.UnauthorizedError(w, nil)
		return
	}

	var req ComAtprotoServerSupplySigningKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Error("error decoding request", "error", err)
		helpers.InputError(w, new("could not decode request body"))
		return
	}

	if err := s.validator.Struct(req); err != nil {
		logger.Error("validation failed", "error", err)
		helpers.InputError(w, new("walletAddress and signature are required"))
		return
	}

	// Decode the 65-byte personal_sign signature.
	sigHex := strings.TrimPrefix(req.Signature, "0x")
	sig, err := hex.DecodeString(sigHex)
	if err != nil || len(sig) != 65 {
		helpers.InputError(w, new("signature must be a 65-byte hex string"))
		return
	}

	// personal_sign uses v=27/28; go-ethereum SigToPub expects v=0/1.
	if sig[64] >= 27 {
		sig[64] -= 27
	}

	// Hash the message the same way personal_sign does:
	// keccak256("\x19Ethereum Signed Message:\n<len><message>")
	msgHash := gethcrypto.Keccak256(
		fmt.Appendf(nil, "\x19Ethereum Signed Message:\n%d%s",
			len(registrationMessage), registrationMessage),
	)

	// Recover the uncompressed public key.
	ecPub, err := gethcrypto.SigToPub(msgHash, sig)
	if err != nil {
		logger.Warn("public key recovery failed", "error", err)
		helpers.InputError(w, new("could not recover public key from signature"))
		return
	}

	// Verify the recovered key matches the claimed wallet address.
	recoveredAddr := gethcrypto.PubkeyToAddress(*ecPub).Hex()
	if !strings.EqualFold(recoveredAddr, req.WalletAddress) {
		logger.Warn("recovered address mismatch",
			"claimed", req.WalletAddress,
			"recovered", recoveredAddr,
		)
		helpers.InputError(w, new("recovered address does not match walletAddress"))
		return
	}

	// Compress the public key (33 bytes).
	keyBytes := gethcrypto.CompressPubkey(ecPub)

	// Validate the compressed key is accepted by the atproto library.
	pubKey, err := atcrypto.ParsePublicBytesK256(keyBytes)
	if err != nil {
		logger.Error("compressed key rejected by atcrypto", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	pubDIDKey := pubKey.DIDKey()

	// Update the PLC DID document if this is a did:plc identity so that the
	// new public key is the active atproto verification method.
	if strings.HasPrefix(repo.Repo.Did, "did:plc:") {
		log, err := identity.FetchDidAuditLog(ctx, nil, repo.Repo.Did)
		if err != nil {
			logger.Error("error fetching DID audit log", "error", err)
			helpers.ServerError(w, nil)
			return
		}

		latest := log[len(log)-1]

		newVerificationMethods := make(map[string]string)
		maps.Copy(newVerificationMethods, latest.Operation.VerificationMethods)
		newVerificationMethods["atproto"] = pubDIDKey

		// Replace the PDS rotation key with the user's wallet key. After
		// this operation the PDS can no longer unilaterally modify the DID
		// document — only the user's Ethereum wallet can authorise future
		// PLC operations. This is the moment the identity becomes
		// user-sovereign.
		newRotationKeys := []string{pubDIDKey}

		op := plc.Operation{
			Type:                "plc_operation",
			VerificationMethods: newVerificationMethods,
			RotationKeys:        newRotationKeys,
			AlsoKnownAs:         latest.Operation.AlsoKnownAs,
			Services:            latest.Operation.Services,
			Prev:                &latest.Cid,
		}

		// The PLC operation is signed by the PDS rotation key, which still
		// has authority over the DID at this point. This is the last
		// operation the PDS will ever be able to sign — it is voluntarily
		// handing over control to the user's wallet key.
		if err := s.plcClient.SignOp(&op); err != nil {
			logger.Error("error signing PLC operation with rotation key", "error", err)
			helpers.ServerError(w, nil)
			return
		}

		if err := s.plcClient.SendOperation(ctx, repo.Repo.Did, &op); err != nil {
			logger.Error("error sending PLC operation", "error", err)
			helpers.ServerError(w, nil)
			return
		}
	}

	// Persist the compressed public key.
	if err := s.db.Exec(ctx,
		"UPDATE repos SET public_key = ? WHERE did = ?",
		nil, keyBytes, repo.Repo.Did,
	).Error; err != nil {
		logger.Error("error updating public key in db", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	// Bust the cached DID document so subsequent requests pick up the change.
	if err := s.passport.BustDoc(ctx, repo.Repo.Did); err != nil {
		logger.Warn("error busting DID doc cache", "error", err)
	}

	logger.Info("public signing key registered via BYOK — rotation key transferred to user",
		"did", repo.Repo.Did,
		"publicKey", pubDIDKey,
	)

	s.writeJSON(w, 200, ComAtprotoServerSupplySigningKeyResponse{
		Did:       repo.Repo.Did,
		PublicKey: pubDIDKey,
	})
}
