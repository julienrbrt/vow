package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/fxamacker/cbor/v2"
)

// ──────────────────────────────────────────────────────────────────────────────
// Attestation parsing (key registration)
// ──────────────────────────────────────────────────────────────────────────────

// attestationObject is the top-level CBOR structure returned by
// navigator.credentials.create().
type attestationObject struct {
	Fmt      string         `cbor:"fmt"`
	AttStmt  map[string]any `cbor:"attStmt"`
	AuthData []byte         `cbor:"authData"`
}

// parseAttestationObject extracts the compressed P-256 public key and the
// credential ID from a WebAuthn attestation object (base64url-encoded CBOR).
//
// Only "none" and "packed" attestation formats are handled; for packed we
// accept self-attestation without verifying the attStmt certificate chain
// (sufficient for a PDS that trusts its own users).
func parseAttestationObject(attestationObjectB64 string) (pubKeyBytes []byte, credentialID []byte, err error) {
	raw, err := base64.RawURLEncoding.DecodeString(attestationObjectB64)
	if err != nil {
		return nil, nil, fmt.Errorf("decode attestationObject: %w", err)
	}

	var ao attestationObject
	if err := cbor.Unmarshal(raw, &ao); err != nil {
		return nil, nil, fmt.Errorf("unmarshal attestationObject CBOR: %w", err)
	}

	pub, cid, err := parseAuthData(ao.AuthData)
	if err != nil {
		return nil, nil, fmt.Errorf("parse authData: %w", err)
	}

	return pub, cid, nil
}

// parseAuthData extracts the credential ID and the compressed P-256 public key
// from a WebAuthn authenticatorData byte string.
//
// The authenticatorData layout is defined in the WebAuthn spec §6.1:
//
//	rpIdHash      [32]byte
//	flags         [1]byte
//	signCount     [4]byte  (big-endian uint32)
//	attestedCredentialData (variable, present when AT flag is set)
//	  aaguid       [16]byte
//	  credIdLen    [2]byte  (big-endian uint16)
//	  credId       [credIdLen]byte
//	  credPubKey   CBOR map (COSE_Key)
func parseAuthData(authData []byte) (pubKeyBytes []byte, credentialID []byte, err error) {
	// Minimum length: 32 (rpIdHash) + 1 (flags) + 4 (signCount) = 37 bytes.
	if len(authData) < 37 {
		return nil, nil, fmt.Errorf("authData too short (%d bytes)", len(authData))
	}

	flags := authData[32]
	// Bit 6 (AT) must be set for attested credential data to be present.
	const flagAT = 0x40
	if flags&flagAT == 0 {
		return nil, nil, fmt.Errorf("authData AT flag not set — no attested credential data")
	}

	if len(authData) < 55 {
		return nil, nil, fmt.Errorf("authData too short for attested credential data (%d bytes)", len(authData))
	}

	// Skip: rpIdHash (32) + flags (1) + signCount (4) + aaguid (16) = 53 bytes.
	credIDLen := int(authData[53])<<8 | int(authData[54])
	offset := 55
	if len(authData) < offset+credIDLen {
		return nil, nil, fmt.Errorf("authData too short for credId (need %d, have %d)", offset+credIDLen, len(authData))
	}

	credentialID = authData[offset : offset+credIDLen]
	offset += credIDLen

	// The remaining bytes are a CBOR-encoded COSE_Key map.
	coseKey := authData[offset:]

	pub, err := parseCOSEKey(coseKey)
	if err != nil {
		return nil, nil, fmt.Errorf("parse COSE key: %w", err)
	}

	return pub, credentialID, nil
}

// parseCOSEKey decodes a CBOR COSE_Key map and returns the compressed P-256
// public key (33 bytes).
//
// Relevant COSE key parameters for EC2 keys (kty=2):
//
//	1  kty     = 2 (EC2)
//	3  alg     = -7 (ES256)
//	-1 crv     = 1 (P-256)
//	-2 x       (32 bytes)
//	-3 y       (32 bytes)
func parseCOSEKey(coseKey []byte) ([]byte, error) {
	// Use integer keys because CBOR maps in COSE use small ints.
	var m map[int]cbor.RawMessage
	if err := cbor.Unmarshal(coseKey, &m); err != nil {
		return nil, fmt.Errorf("unmarshal COSE_Key: %w", err)
	}

	// Check kty == 2 (EC2).
	var kty int
	if raw, ok := m[1]; ok {
		if err := cbor.Unmarshal(raw, &kty); err != nil {
			return nil, fmt.Errorf("decode kty: %w", err)
		}
	}
	if kty != 2 {
		return nil, fmt.Errorf("unsupported COSE key type %d (expected 2 for EC2)", kty)
	}

	// Check crv == 1 (P-256).
	var crv int
	if raw, ok := m[-1]; ok {
		if err := cbor.Unmarshal(raw, &crv); err != nil {
			return nil, fmt.Errorf("decode crv: %w", err)
		}
	}
	if crv != 1 {
		return nil, fmt.Errorf("unsupported COSE curve %d (expected 1 for P-256)", crv)
	}

	var xBytes, yBytes []byte
	if raw, ok := m[-2]; ok {
		if err := cbor.Unmarshal(raw, &xBytes); err != nil {
			return nil, fmt.Errorf("decode x: %w", err)
		}
	}
	if raw, ok := m[-3]; ok {
		if err := cbor.Unmarshal(raw, &yBytes); err != nil {
			return nil, fmt.Errorf("decode y: %w", err)
		}
	}

	if len(xBytes) != 32 || len(yBytes) != 32 {
		return nil, fmt.Errorf("unexpected key coordinate lengths (x=%d, y=%d)", len(xBytes), len(yBytes))
	}

	// Compress the public key: prefix 0x02 if y is even, 0x03 if y is odd.
	prefix := byte(0x02)
	if yBytes[31]&1 == 1 {
		prefix = 0x03
	}

	compressed := make([]byte, 33)
	compressed[0] = prefix
	copy(compressed[1:], xBytes)

	return compressed, nil
}

// ──────────────────────────────────────────────────────────────────────────────
// Assertion verification (signing operations & account deletion)
// ──────────────────────────────────────────────────────────────────────────────

// clientDataJSON is the parsed form of the clientDataJSON field returned by
// navigator.credentials.get().
type clientDataJSON struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"` // base64url
	Origin    string `json:"origin"`
}

// verifyAssertion verifies a WebAuthn assertion and returns the raw 64-byte
// (r‖s) ECDSA signature suitable for use in ATProto commits and JWTs.
//
// Parameters:
//   - pubKeyCompressed: 33-byte compressed P-256 public key stored in the DB.
//   - expectedChallenge: the raw challenge bytes the server originally sent.
//   - clientDataJSONBytes: the clientDataJSON bytes from the assertion response.
//   - authenticatorDataBytes: the authenticatorData bytes from the assertion response.
//   - signatureDER: the DER-encoded ECDSA signature from the assertion response.
//   - rpID: the relying party ID (hostname), e.g. "example.com".
func verifyAssertion(
	pubKeyCompressed []byte,
	expectedChallenge []byte,
	clientDataJSONBytes []byte,
	authenticatorDataBytes []byte,
	signatureDER []byte,
	rpID string,
) (rawSig []byte, err error) {
	// ── 1. Parse and validate clientDataJSON ─────────────────────────────
	var cd clientDataJSON
	if err := json.Unmarshal(clientDataJSONBytes, &cd); err != nil {
		return nil, fmt.Errorf("unmarshal clientDataJSON: %w", err)
	}

	if cd.Type != "webauthn.get" {
		return nil, fmt.Errorf("unexpected clientData type %q (want webauthn.get)", cd.Type)
	}

	// The challenge in clientDataJSON is base64url-encoded (the browser
	// re-encodes the ArrayBuffer it was given).
	gotChallenge, err := base64.RawURLEncoding.DecodeString(cd.Challenge)
	if err != nil {
		// Some browsers include padding — try with std encoding as fallback.
		gotChallenge, err = base64.URLEncoding.DecodeString(cd.Challenge)
		if err != nil {
			return nil, fmt.Errorf("decode challenge from clientDataJSON: %w", err)
		}
	}

	if len(gotChallenge) != len(expectedChallenge) {
		return nil, fmt.Errorf("challenge length mismatch (got %d, want %d)", len(gotChallenge), len(expectedChallenge))
	}
	for i := range expectedChallenge {
		if gotChallenge[i] != expectedChallenge[i] {
			return nil, fmt.Errorf("challenge mismatch")
		}
	}

	// ── 2. Validate authenticatorData ────────────────────────────────────
	if len(authenticatorDataBytes) < 37 {
		return nil, fmt.Errorf("authenticatorData too short (%d bytes)", len(authenticatorDataBytes))
	}

	// Verify rpIdHash matches SHA-256(rpID).
	rpIDHash := sha256.Sum256([]byte(rpID))
	for i := range 32 {
		if authenticatorDataBytes[i] != rpIDHash[i] {
			return nil, fmt.Errorf("rpIdHash mismatch")
		}
	}

	// Check UP (user presence) flag — bit 0 must be set.
	flags := authenticatorDataBytes[32]
	const flagUP = 0x01
	if flags&flagUP == 0 {
		return nil, fmt.Errorf("user presence flag not set")
	}

	// ── 3. Reconstruct and verify the signed message ──────────────────────
	// WebAuthn signed data = authenticatorData ‖ SHA-256(clientDataJSON).
	cdHash := sha256.Sum256(clientDataJSONBytes)
	signedData := make([]byte, len(authenticatorDataBytes)+32)
	copy(signedData, authenticatorDataBytes)
	copy(signedData[len(authenticatorDataBytes):], cdHash[:])

	// ── 4. Parse the DER signature ────────────────────────────────────────
	rawSig64, err := derToRawECDSA(signatureDER)
	if err != nil {
		return nil, fmt.Errorf("parse DER signature: %w", err)
	}

	// ── 5. Verify the P-256 signature ─────────────────────────────────────
	pub, err := decompressP256(pubKeyCompressed)
	if err != nil {
		return nil, fmt.Errorf("decompress public key: %w", err)
	}

	digest := sha256.Sum256(signedData)
	r := new(big.Int).SetBytes(rawSig64[:32])
	s := new(big.Int).SetBytes(rawSig64[32:])

	if !ecdsa.Verify(pub, digest[:], r, s) {
		return nil, fmt.Errorf("signature verification failed")
	}

	return rawSig64, nil
}

// ──────────────────────────────────────────────────────────────────────────────
// DER → raw (r‖s) conversion
// ──────────────────────────────────────────────────────────────────────────────

// derToRawECDSA parses a DER-encoded ECDSA signature (as produced by a WebAuthn
// authenticator) and returns the 64-byte (r‖s) concatenation with each
// component zero-padded to 32 bytes.
func derToRawECDSA(der []byte) ([]byte, error) {
	var sig struct {
		R, S *big.Int
	}
	rest, err := asn1.Unmarshal(der, &sig)
	if err != nil {
		return nil, fmt.Errorf("asn1 unmarshal: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("trailing bytes after DER signature (%d bytes)", len(rest))
	}
	if sig.R == nil || sig.S == nil {
		return nil, fmt.Errorf("nil r or s in DER signature")
	}

	out := make([]byte, 64)
	rBytes := sig.R.Bytes()
	sBytes := sig.S.Bytes()

	if len(rBytes) > 32 || len(sBytes) > 32 {
		return nil, fmt.Errorf("r or s component exceeds 32 bytes (r=%d, s=%d)", len(rBytes), len(sBytes))
	}

	copy(out[32-len(rBytes):32], rBytes)
	copy(out[64-len(sBytes):64], sBytes)

	return out, nil
}

// ──────────────────────────────────────────────────────────────────────────────
// Key helpers
// ──────────────────────────────────────────────────────────────────────────────

// decompressP256 decompresses a 33-byte compressed P-256 public key into an
// *ecdsa.PublicKey.
func decompressP256(compressed []byte) (*ecdsa.PublicKey, error) {
	if len(compressed) != 33 {
		return nil, fmt.Errorf("expected 33-byte compressed key, got %d bytes", len(compressed))
	}

	curve := elliptic.P256()
	x, y := elliptic.UnmarshalCompressed(curve, compressed)
	if x == nil {
		return nil, fmt.Errorf("failed to unmarshal compressed P-256 key")
	}

	// Setting the PublicKey coordinate fields directly is deprecated; encode
	// the point in the uncompressed SEC 1 form and parse it instead.
	uncompressed := make([]byte, 65)
	uncompressed[0] = 0x04
	x.FillBytes(uncompressed[1:33])
	y.FillBytes(uncompressed[33:65])

	pub, err := ecdsa.ParseUncompressedPublicKey(curve, uncompressed)
	if err != nil {
		return nil, fmt.Errorf("parse P-256 public key: %w", err)
	}

	return pub, nil
}
