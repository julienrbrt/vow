package server

import (
	"encoding/base64"
	"encoding/json"
	"maps"
	"net/http"
	"strings"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"pkg.rbrt.fr/vow/identity"
	"pkg.rbrt.fr/vow/internal/helpers"
	"pkg.rbrt.fr/vow/models"
	"pkg.rbrt.fr/vow/plc"
)

// SupplySigningKeyRequest is sent by the account page to register a WebAuthn
// passkey as the account's signing key. The browser calls
// navigator.credentials.create() and forwards the raw attestation response
// fields here; the server parses the CBOR attestation object, extracts the
// P-256 public key, and stores it alongside the credential ID.
type SupplySigningKeyRequest struct {
	// ClientDataJSON is the base64url-encoded clientDataJSON bytes from the
	// AuthenticatorAttestationResponse.
	ClientDataJSON string `json:"clientDataJSON" validate:"required"`
	// AttestationObject is the base64url-encoded attestationObject CBOR from
	// the AuthenticatorAttestationResponse.
	AttestationObject string `json:"attestationObject" validate:"required"`
}

type SupplySigningKeyResponse struct {
	Did          string `json:"did"`
	PublicKey    string `json:"publicKey"`    // did:key for atproto (commit signing, passkey)
	ServiceKey   string `json:"serviceKey"`   // did:key for atproto_service (service-auth, PDS server key)
	CredentialID string `json:"credentialId"` // base64url credential ID
}

// handleSupplySigningKey registers a WebAuthn passkey for the authenticated
// account. The private key never leaves the authenticator; the PDS stores only
// the compressed P-256 public key and the credential ID.
//
// On success the account's PLC DID document is updated with two changes:
//
//  1. verificationMethods["atproto"] = passkey did:key
//     The passkey becomes the commit-signing key. Every repo write requires a
//     user-presence gesture from this point on.
//
//  2. verificationMethods["atproto_service"] = PDS server did:key
//     The PDS server key is registered for service-auth JWT signing. This lets
//     the PDS issue service-auth tokens for background requests (feed loading,
//     notifications, proxied reads) without prompting the passkey each time.
//     AppViews that implement the atproto_service fallback (per the RFC at
//     https://tangled.org/strings/did:plc:7kpq3n7brenbgyp2gx36hl6x/3mgqmwxzvlu22)
//     will accept these tokens. Older verifiers fall back to #atproto and will
//     reject them — that is the known limitation until the spec change lands.
//
//  3. rotationKeys = [passkey did:key]
//     The PDS rotation key is removed. Only the user's passkey can authorise
//     future PLC operations.
func (s *Server) handleSupplySigningKey(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := s.logger.With("name", "handleSupplySigningKey")

	repo, ok := getContextValue[*models.RepoActor](r, contextKeyRepo)
	if !ok {
		helpers.UnauthorizedError(w, nil)
		return
	}

	var req SupplySigningKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Error("error decoding request", "error", err)
		helpers.InputError(w, new("could not decode request body"))
		return
	}

	if err := s.validator.Struct(req); err != nil {
		logger.Error("validation failed", "error", err)
		helpers.InputError(w, new("clientDataJSON and attestationObject are required"))
		return
	}

	// Parse the attestation object and extract the P-256 public key +
	// credential ID. We accept both "none" and self-attestation.
	keyBytes, credentialID, err := parseAttestationObject(req.AttestationObject)
	if err != nil {
		logger.Warn("attestation parsing failed", "error", err)
		helpers.InputError(w, new("could not parse attestation object"))
		return
	}

	// Validate the compressed key is a well-formed P-256 point.
	pubKey, err := atcrypto.ParsePublicBytesP256(keyBytes)
	if err != nil {
		logger.Error("compressed P-256 key rejected by atcrypto", "error", err)
		helpers.InputError(w, new("invalid P-256 public key in attestation"))
		return
	}

	pubDIDKey := pubKey.DIDKey()

	// Derive the PDS server did:key for the atproto_service slot.
	pdsDIDKey, err := s.pdsDIDKey()
	if err != nil {
		logger.Error("error deriving PDS did:key", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	// Update the PLC DID document with the two-key structure.
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
		// Commit-signing key: the user's passkey. Every repo write requires
		// passkey usage.
		newVerificationMethods["atproto"] = pubDIDKey
		// Service-auth signing key: the PDS server key. Used for background
		// infrastructure requests that must not require a passkey.
		// Verifiers that implement the atproto_service RFC will accept tokens
		// signed by this key; others fall back to #atproto (known limitation).
		newVerificationMethods["atproto_service"] = pdsDIDKey

		// Replace the PDS rotation key with the passkey's did:key. After this
		// operation the PDS can no longer unilaterally modify the DID document
		// — only the user's passkey can authorise future PLC operations.
		newRotationKeys := []string{pubDIDKey}

		op := plc.Operation{
			Type:                "plc_operation",
			VerificationMethods: newVerificationMethods,
			RotationKeys:        newRotationKeys,
			AlsoKnownAs:         latest.Operation.AlsoKnownAs,
			Services:            latest.Operation.Services,
			Prev:                &latest.Cid,
		}

		// The PDS rotation key signs this PLC operation — this is the last
		// PLC operation the PDS will ever be able to sign on behalf of the
		// user. It is voluntarily handing over control to the passkey.
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

	// Persist the compressed P-256 public key and credential ID.
	if err := s.db.Exec(ctx,
		"UPDATE repos SET public_key = ?, credential_id = ? WHERE did = ?",
		nil, keyBytes, credentialID, repo.Repo.Did,
	).Error; err != nil {
		logger.Error("error updating public key and credential ID in db", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	// Bust the cached DID document so subsequent requests pick up the change.
	if err := s.passport.BustDoc(ctx, repo.Repo.Did); err != nil {
		logger.Warn("error busting DID doc cache", "error", err)
	}

	logger.Info("passkey registered — rotation key transferred to user",
		"did", repo.Repo.Did,
		"publicKey", pubDIDKey,
		"serviceKey", pdsDIDKey,
		"credentialIDLen", len(credentialID),
	)

	s.writeJSON(w, 200, SupplySigningKeyResponse{
		Did:          repo.Repo.Did,
		PublicKey:    pubDIDKey,
		ServiceKey:   pdsDIDKey,
		CredentialID: base64.RawURLEncoding.EncodeToString(credentialID),
	})
}
