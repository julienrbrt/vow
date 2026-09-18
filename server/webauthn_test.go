package server

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"gotest.tools/v3/assert"
)

// generateP256Key returns a random P-256 key pair.
func generateP256Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NilError(t, err)

	return key
}

// compressPoint encodes a P-256 public key in its 33-byte compressed form
// (0x02/0x03 prefix ‖ x).
func compressPoint(t *testing.T, pub *ecdsa.PublicKey) []byte {
	t.Helper()

	uncompressed, err := pub.Bytes()
	assert.NilError(t, err)

	compressed := make([]byte, 33)
	compressed[0] = 0x02
	if uncompressed[64]&1 == 1 {
		compressed[0] = 0x03
	}
	copy(compressed[1:], uncompressed[1:33])

	return compressed
}

func TestDecompressP256RoundTrip(t *testing.T) {
	for range 10 {
		priv := generateP256Key(t)
		compressed := compressPoint(t, &priv.PublicKey)

		pub, err := decompressP256(compressed)
		assert.NilError(t, err)

		want, err := priv.PublicKey.Bytes()
		assert.NilError(t, err)
		got, err := pub.Bytes()
		assert.NilError(t, err)
		assert.DeepEqual(t, want, got)

		// The decompressed key must verify signatures made by the original key.
		digest := sha256.Sum256([]byte("vow"))
		sig, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
		assert.NilError(t, err)
		assert.Assert(t, ecdsa.VerifyASN1(pub, digest[:], sig))
	}
}

// Keys with a leading zero byte in a coordinate exercise zero-padding of the
// 32-byte encodings.
func TestDecompressP256LeadingZeroCoordinate(t *testing.T) {
	var priv *ecdsa.PrivateKey
	for range 100000 {
		candidate := generateP256Key(t)
		uncompressed, err := candidate.PublicKey.Bytes()
		assert.NilError(t, err)
		if uncompressed[1] == 0 || uncompressed[33] == 0 {
			priv = candidate
			break
		}
	}
	if priv == nil {
		t.Skip("no key with a leading zero coordinate found")
	}

	pub, err := decompressP256(compressPoint(t, &priv.PublicKey))
	assert.NilError(t, err)

	want, err := priv.PublicKey.Bytes()
	assert.NilError(t, err)
	got, err := pub.Bytes()
	assert.NilError(t, err)
	assert.DeepEqual(t, want, got)
}

func TestDecompressP256InvalidKeys(t *testing.T) {
	valid := compressPoint(t, &generateP256Key(t).PublicKey)

	tests := []struct {
		name string
		key  []byte
	}{
		{"empty", nil},
		{"too short", valid[:32]},
		{"too long", append(valid[:33:33], 0x00)},
		{"invalid prefix", append([]byte{0x05}, valid[1:]...)},
		{"point not on curve", append([]byte{0x02}, bytes.Repeat([]byte{0x11}, 32)...)},
		{"point at infinity prefix", append([]byte{0x00}, valid[1:]...)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := decompressP256(tt.key)
			assert.ErrorContains(t, err, "")
		})
	}
}

// coseKey builds a CBOR-encoded COSE_Key map.
func coseKey(t *testing.T, kty, crv int, x, y []byte) []byte {
	t.Helper()

	m := map[int]any{1: kty, 3: -7, -1: crv, -2: x, -3: y}
	raw, err := cbor.Marshal(m)
	assert.NilError(t, err)

	return raw
}

func TestParseCOSEKey(t *testing.T) {
	priv := generateP256Key(t)
	uncompressed, err := priv.PublicKey.Bytes()
	assert.NilError(t, err)
	x, y := uncompressed[1:33], uncompressed[33:65]

	pub, err := parseCOSEKey(coseKey(t, 2, 1, x, y))
	assert.NilError(t, err)
	assert.Equal(t, len(pub), 33)
	assert.Equal(t, pub[0], compressPoint(t, &priv.PublicKey)[0])
	assert.DeepEqual(t, pub[1:], x)
}

func TestParseCOSEKeyOddY(t *testing.T) {
	var priv *ecdsa.PrivateKey
	for range 1000 {
		candidate := generateP256Key(t)
		uncompressed, err := candidate.PublicKey.Bytes()
		assert.NilError(t, err)
		if uncompressed[64]&1 == 1 {
			priv = candidate
			break
		}
	}
	if priv == nil {
		t.Skip("no key with odd y found")
	}

	uncompressed, err := priv.PublicKey.Bytes()
	assert.NilError(t, err)

	pub, err := parseCOSEKey(coseKey(t, 2, 1, uncompressed[1:33], uncompressed[33:65]))
	assert.NilError(t, err)
	assert.Equal(t, pub[0], byte(0x03))
}

func TestParseCOSEKeyInvalid(t *testing.T) {
	x := bytes.Repeat([]byte{0x01}, 32)
	y := bytes.Repeat([]byte{0x02}, 32)

	tests := []struct {
		name string
		key  []byte
	}{
		{"invalid cbor", []byte("not cbor")},
		{"wrong kty", coseKey(t, 4, 1, x, y)},
		{"missing kty", mustCBOR(t, map[int]any{3: -7, -1: 1, -2: x, -3: y})},
		{"wrong crv", coseKey(t, 2, 3, x, y)},
		{"missing crv", mustCBOR(t, map[int]any{1: 2, 3: -7, -2: x, -3: y})},
		{"short x", coseKey(t, 2, 1, x[:31], y)},
		{"short y", coseKey(t, 2, 1, x, y[:31])},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseCOSEKey(tt.key)
			assert.ErrorContains(t, err, "")
		})
	}
}

func mustCBOR(t *testing.T, v any) []byte {
	t.Helper()

	raw, err := cbor.Marshal(v)
	assert.NilError(t, err)

	return raw
}

// authData builds authenticatorData with attested credential data.
func authData(t *testing.T, rpID string, flags byte, credID, coseKey []byte) []byte {
	t.Helper()

	out := make([]byte, 0, 55+len(credID)+len(coseKey))
	rpIDHash := sha256.Sum256([]byte(rpID))
	out = append(out, rpIDHash[:]...)
	out = append(out, flags)
	out = binary.BigEndian.AppendUint32(out, 0) // signCount
	out = append(out, make([]byte, 16)...)      // aaguid
	out = binary.BigEndian.AppendUint16(out, uint16(len(credID)))
	out = append(out, credID...)

	return append(out, coseKey...)
}

func TestParseAuthData(t *testing.T) {
	priv := generateP256Key(t)
	credID := []byte("credential-id")
	cose := coseKey(t, 2, 1, keyX(t, priv), keyY(t, priv))

	pub, gotCredID, err := parseAuthData(authData(t, "example.com", 0x41, credID, cose))
	assert.NilError(t, err)
	assert.DeepEqual(t, gotCredID, credID)
	assert.DeepEqual(t, pub, compressPoint(t, &priv.PublicKey))
}

func keyX(t *testing.T, priv *ecdsa.PrivateKey) []byte {
	t.Helper()

	uncompressed, err := priv.PublicKey.Bytes()
	assert.NilError(t, err)

	return uncompressed[1:33]
}

func keyY(t *testing.T, priv *ecdsa.PrivateKey) []byte {
	t.Helper()

	uncompressed, err := priv.PublicKey.Bytes()
	assert.NilError(t, err)

	return uncompressed[33:65]
}

func TestParseAuthDataInvalid(t *testing.T) {
	priv := generateP256Key(t)
	credID := []byte("credential-id")
	valid := authData(t, "example.com", 0x41, credID, coseKey(t, 2, 1, keyX(t, priv), keyY(t, priv)))

	// Short credID length so truncation stays within attested credential data.
	tests := []struct {
		name string
		data []byte
	}{
		{"too short", valid[:36]},
		{"at flag not set", authData(t, "example.com", 0x01, credID, coseKey(t, 2, 1, keyX(t, priv), keyY(t, priv)))[:37]},
		{"truncated credential data", valid[:50]},
		{"credID exceeds input", valid[:57]},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := parseAuthData(tt.data)
			assert.ErrorContains(t, err, "")
		})
	}
}

// signAssertion produces a DER signature over the WebAuthn signed data
// (authenticatorData ‖ SHA-256(clientDataJSON)) using ecdsa.Sign, so the
// expected raw (r‖s) form is known exactly.
func signAssertion(t *testing.T, priv *ecdsa.PrivateKey, authDataBytes, clientDataJSONBytes []byte) (der, raw []byte) {
	t.Helper()

	cdHash := sha256.Sum256(clientDataJSONBytes)
	signed := append(append([]byte{}, authDataBytes...), cdHash[:]...)
	digest := sha256.Sum256(signed)

	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	assert.NilError(t, err)

	der, err = asn1.Marshal(struct {
		R, S *big.Int
	}{r, s})
	assert.NilError(t, err)

	raw = make([]byte, 64)
	r.FillBytes(raw[:32])
	s.FillBytes(raw[32:])

	return der, raw
}

func TestVerifyAssertion(t *testing.T) {
	const rpID = "example.com"

	priv := generateP256Key(t)
	pubKeyCompressed := compressPoint(t, &priv.PublicKey)
	challenge := bytes.Repeat([]byte{0xAB}, 32)
	authDataBytes := authData(t, rpID, 0x01, nil, nil)
	clientData := mustJSON(t, clientDataJSON{
		Type:      "webauthn.get",
		Challenge: base64.RawURLEncoding.EncodeToString(challenge),
		Origin:    "https://" + rpID,
	})

	der, raw := signAssertion(t, priv, authDataBytes, clientData)

	got, err := verifyAssertion(pubKeyCompressed, challenge, clientData, authDataBytes, der, rpID)
	assert.NilError(t, err)
	assert.DeepEqual(t, got, raw)
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()

	raw, err := json.Marshal(v)
	assert.NilError(t, err)

	return raw
}

func TestVerifyAssertionPaddedChallenge(t *testing.T) {
	const rpID = "example.com"

	priv := generateP256Key(t)
	challenge := bytes.Repeat([]byte{0xCD}, 32)
	authDataBytes := authData(t, rpID, 0x01, nil, nil)
	clientData := mustJSON(t, clientDataJSON{
		Type:      "webauthn.get",
		Challenge: base64.URLEncoding.EncodeToString(challenge),
		Origin:    "https://" + rpID,
	})

	der, _ := signAssertion(t, priv, authDataBytes, clientData)

	_, err := verifyAssertion(compressPoint(t, &priv.PublicKey), challenge, clientData, authDataBytes, der, rpID)
	assert.NilError(t, err)
}

func TestVerifyAssertionInvalid(t *testing.T) {
	const rpID = "example.com"

	priv := generateP256Key(t)
	otherKey := generateP256Key(t)
	challenge := bytes.Repeat([]byte{0xAB}, 32)
	authDataBytes := authData(t, rpID, 0x01, nil, nil)
	clientData := mustJSON(t, clientDataJSON{
		Type:      "webauthn.get",
		Challenge: base64.RawURLEncoding.EncodeToString(challenge),
		Origin:    "https://" + rpID,
	})
	der, _ := signAssertion(t, priv, authDataBytes, clientData)
	otherChallenge := bytes.Repeat([]byte{0x12}, 32)

	tests := []struct {
		name       string
		pubKey     []byte
		challenge  []byte
		clientData []byte
		authData   []byte
		signature  []byte
		rpID       string
	}{
		{"invalid client data json", compressPoint(t, &priv.PublicKey), challenge, []byte("{"), authDataBytes, der, rpID},
		{"wrong type", compressPoint(t, &priv.PublicKey), challenge, mustJSON(t, clientDataJSON{Type: "webauthn.create", Challenge: base64.RawURLEncoding.EncodeToString(challenge), Origin: "https://" + rpID}), authDataBytes, der, rpID},
		{"undecodable challenge", compressPoint(t, &priv.PublicKey), challenge, mustJSON(t, clientDataJSON{Type: "webauthn.get", Challenge: "!!", Origin: "https://" + rpID}), authDataBytes, der, rpID},
		{"wrong challenge", compressPoint(t, &priv.PublicKey), otherChallenge, clientData, authDataBytes, der, rpID},
		{"wrong rp id", compressPoint(t, &priv.PublicKey), challenge, clientData, authDataBytes, der, "other.com"},
		{"auth data too short", compressPoint(t, &priv.PublicKey), challenge, clientData, authDataBytes[:36], der, rpID},
		{"user presence not set", compressPoint(t, &priv.PublicKey), challenge, clientData, authData(t, rpID, 0x00, nil, nil), der, rpID},
		{"wrong rp id hash", compressPoint(t, &priv.PublicKey), challenge, clientData, authData(t, "other.com", 0x01, nil, nil), der, rpID},
		{"invalid der", compressPoint(t, &priv.PublicKey), challenge, clientData, authDataBytes, []byte("not der"), rpID},
		{"wrong key", compressPoint(t, &otherKey.PublicKey), challenge, clientData, authDataBytes, der, rpID},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := verifyAssertion(tt.pubKey, tt.challenge, tt.clientData, tt.authData, tt.signature, tt.rpID)
			assert.ErrorContains(t, err, "")
		})
	}
}

func TestDerToRawECDSA(t *testing.T) {
	priv := generateP256Key(t)
	digest := sha256.Sum256([]byte("vow"))

	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	assert.NilError(t, err)

	der, err := asn1.Marshal(struct {
		R, S *big.Int
	}{r, s})
	assert.NilError(t, err)

	raw, err := derToRawECDSA(der)
	assert.NilError(t, err)
	assert.Equal(t, len(raw), 64)

	want := make([]byte, 64)
	r.FillBytes(want[:32])
	s.FillBytes(want[32:])
	assert.DeepEqual(t, raw, want)
}

func TestDerToRawECDSAInvalid(t *testing.T) {
	priv := generateP256Key(t)
	digest := sha256.Sum256([]byte("vow"))

	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	assert.NilError(t, err)

	valid, err := asn1.Marshal(struct {
		R, S *big.Int
	}{r, s})
	assert.NilError(t, err)

	oversized, err := asn1.Marshal(struct {
		R, S *big.Int
	}{new(big.Int).Lsh(big.NewInt(1), 300), s})
	assert.NilError(t, err)

	tests := []struct {
		name string
		der  []byte
	}{
		{"not der", []byte("not der")},
		{"trailing bytes", append(append([]byte{}, valid...), 0x00)},
		{"oversized r", oversized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := derToRawECDSA(tt.der)
			assert.ErrorContains(t, err, "")
		})
	}
}
