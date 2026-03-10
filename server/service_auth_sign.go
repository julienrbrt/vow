package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"pkg.rbrt.fr/vow/models"
)

// serviceAuthCacheEntry holds a cached service-auth JWT and its expiry time.
type serviceAuthCacheEntry struct {
	token     string
	expiresAt time.Time
}

// serviceAuthCache is a simple in-memory cache for service-auth JWTs keyed by
// (did, aud, lxm). Service auth tokens are short-lived (a few minutes) and
// signing each one requires a round-trip to the user's Ethereum wallet. By
// caching tokens we reduce the number of wallet prompts from "every proxied
// XRPC call" to roughly "once every few minutes per (aud, lxm) pair".
type serviceAuthCache struct {
	mu      sync.Mutex
	entries map[string]serviceAuthCacheEntry
}

func newServiceAuthCache() *serviceAuthCache {
	return &serviceAuthCache{
		entries: make(map[string]serviceAuthCacheEntry),
	}
}

// serviceAuthTokenLifetime is how long a cached service-auth JWT is valid for.
// A longer lifetime means fewer wallet prompts but a wider window during which
// a leaked token could be replayed. 30 minutes is a reasonable trade-off: the
// token is scoped to a single (aud, lxm) pair so the blast radius is small.
const serviceAuthTokenLifetime = 30 * time.Minute

// serviceAuthReuseMargin is how far before expiry we stop reusing a cached
// token and sign a fresh one. This avoids handing out a token that expires
// mid-flight.
const serviceAuthReuseMargin = 15 * time.Second

func cacheKey(did, aud, lxm string) string {
	return did + "\x00" + aud + "\x00" + lxm
}

// get returns a cached token if one exists and is still usable (i.e. will not
// expire within serviceAuthReuseMargin). Returns ("", false) on cache miss.
func (c *serviceAuthCache) get(did, aud, lxm string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.entries[cacheKey(did, aud, lxm)]
	if !ok {
		return "", false
	}
	if time.Now().Add(serviceAuthReuseMargin).After(entry.expiresAt) {
		// Too close to expiry — treat as a miss so we sign a fresh one.
		delete(c.entries, cacheKey(did, aud, lxm))
		return "", false
	}
	return entry.token, true
}

// put stores a signed token in the cache.
func (c *serviceAuthCache) put(did, aud, lxm, token string, expiresAt time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[cacheKey(did, aud, lxm)] = serviceAuthCacheEntry{
		token:     token,
		expiresAt: expiresAt,
	}
}

// evictExpired removes entries whose tokens have already expired. Call this
// periodically to prevent unbounded growth.
func (c *serviceAuthCache) evictExpired() {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	for k, entry := range c.entries {
		if now.After(entry.expiresAt) {
			delete(c.entries, k)
		}
	}
}

// startEvictionLoop runs a background goroutine that periodically prunes
// expired entries from the cache. It stops when ctx is cancelled.
func (c *serviceAuthCache) startEvictionLoop(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				c.evictExpired()
			case <-ctx.Done():
				return
			}
		}
	}()
}

// signServiceAuthJWT returns a signed ES256K service-auth JWT for the given
// (aud, lxm) pair, reusing a cached token when possible. Only when no cached
// token is available does it send a signing request to the user's wallet via
// the SignerHub WebSocket.
//
// The returned string is a fully formed "header.payload.signature" JWT ready to
// be placed in an Authorization: Bearer header.
//
// lxm may be empty, in which case no "lxm" claim is included.
func (s *Server) signServiceAuthJWT(
	ctx context.Context,
	repo *models.RepoActor,
	aud string,
	lxm string,
	exp int64,
) (string, error) {
	if len(repo.PublicKey) == 0 {
		return "", fmt.Errorf("no public key registered for account %s", repo.Repo.Did)
	}

	did := repo.Repo.Did

	// ── Check cache ───────────────────────────────────────────────────────
	// For explicitly requested tokens (getServiceAuth) the caller may set a
	// custom exp. We only cache tokens whose lifetime we control (proxy
	// calls), identified by exp == 0 (meaning "use the default").
	useCache := exp == 0
	if useCache {
		if cached, ok := s.serviceAuthCache.get(did, aud, lxm); ok {
			return cached, nil
		}
	}

	// ── Build header + payload ────────────────────────────────────────────
	header := map[string]string{
		"alg": "ES256K",
		"crv": "secp256k1",
		"typ": "JWT",
	}
	hj, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshaling JWT header: %w", err)
	}
	encHeader := strings.TrimRight(base64.RawURLEncoding.EncodeToString(hj), "=")

	now := time.Now().Unix()
	var expiresAt time.Time
	if exp == 0 {
		expiresAt = time.Now().Add(serviceAuthTokenLifetime)
		exp = expiresAt.Unix()
	} else {
		expiresAt = time.Unix(exp, 0)
	}

	claims := map[string]any{
		"iss": did,
		"aud": aud,
		"jti": uuid.NewString(),
		"exp": exp,
		"iat": now,
	}
	if lxm != "" {
		claims["lxm"] = lxm
	}

	pj, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshaling JWT payload: %w", err)
	}
	encPayload := strings.TrimRight(base64.RawURLEncoding.EncodeToString(pj), "=")

	// signingInput is what the JWT spec calls the "message to be signed":
	// base64url(header) + "." + base64url(payload).
	signingInput := encHeader + "." + encPayload

	// The wallet signs the SHA-256 hash of the signing input, which is what
	// ES256K requires. We pass the raw signingInput bytes as the payload;
	// HashAndVerifyLenient on the verification side hashes them before
	// verifying, matching what personal_sign does after EIP-191 prefix
	// stripping (or eth_sign which skips the prefix).
	//
	// We send the SHA-256 pre-image (the signingInput string) rather than the
	// hash so the signer can display it meaningfully and so the wallet can
	// apply its own hashing. This matches the pattern used for commit signing.
	hash := sha256.Sum256([]byte(signingInput))
	payloadB64 := base64.RawURLEncoding.EncodeToString(hash[:])

	requestID := uuid.NewString()
	signerDeadline := time.Now().Add(signerRequestTimeout)

	ops := []PendingWriteOp{
		{
			Type:       "service_auth",
			Collection: aud,
			Rkey:       lxm,
		},
	}

	msgBytes, err := buildSignRequestMsg(requestID, did, payloadB64, ops, signerDeadline)
	if err != nil {
		return "", fmt.Errorf("building sign request message: %w", err)
	}

	signCtx, cancel := context.WithDeadline(ctx, signerDeadline)
	defer cancel()

	sigBytes, err := s.signerHub.RequestSignature(signCtx, did, requestID, msgBytes)
	if err != nil {
		return "", err
	}

	// sigBytes is the raw compact (r||s) or EIP-191 signature returned by the
	// wallet. Trim to 64 bytes (r||s) if the wallet appended a recovery byte.
	if len(sigBytes) == 65 {
		sigBytes = sigBytes[:64]
	}
	if len(sigBytes) != 64 {
		return "", fmt.Errorf("unexpected signature length %d (want 64)", len(sigBytes))
	}

	encSig := strings.TrimRight(base64.RawURLEncoding.EncodeToString(sigBytes), "=")
	token := signingInput + "." + encSig

	// ── Populate cache ────────────────────────────────────────────────────
	if useCache {
		s.serviceAuthCache.put(did, aud, lxm, token, expiresAt)
	}

	return token, nil
}
