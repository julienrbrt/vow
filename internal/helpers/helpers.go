package helpers

import (
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/rand"
	"net/http"
	"net/url"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

var (
	// ErrSignerNotConnected is the sentinel returned when no wallet is connected.
	ErrSignerNotConnected = errors.New("signer not connected")

	// ErrSignerRejected is the sentinel returned when the wallet rejected the
	// signing request.
	ErrSignerRejected = errors.New("signer rejected")

	// ErrSignerTimeout is the sentinel returned when the wallet did not respond
	// within the deadline.
	ErrSignerTimeout = errors.New("signer timeout")
)

// Invite code alphabet.
var letters = []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func InputError(w http.ResponseWriter, custom *string) {
	msg := "InvalidRequest"
	if custom != nil {
		msg = *custom
	}
	genericError(w, http.StatusBadRequest, msg)
}

// HandleSignerError maps the three signer sentinel errors to ATProto-compatible
// HTTP 400 responses with descriptive error codes, and falls back to a 500 for
// anything else. Returns true if err was non-nil (so callers can use it as a
// guard).
//
// The error codes follow the ATProto convention used by the official PDS:
//   - "AccountNotFound"  — no wallet tab is open / connected.
//   - "UserTookDownRepo" — the user explicitly rejected the signing prompt.
//   - "RepoDeactivated"  — the signing deadline elapsed with no response.
//
// These are the closest standard codes to what happened; they tell AppViews
// and clients something meaningful without leaking internal implementation
// details.
func HandleSignerError(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}
	switch {
	case errors.Is(err, ErrSignerNotConnected):
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":   "AccountNotFound",
			"message": "No wallet signer is connected for this account. Open the account page and keep it in a browser tab.",
		})
	case errors.Is(err, ErrSignerRejected):
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":   "UserTookDownRepo",
			"message": "The wallet rejected the signing request.",
		})
	case errors.Is(err, ErrSignerTimeout):
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":   "RepoDeactivated",
			"message": "The wallet did not respond within the signing deadline.",
		})
	default:
		ServerError(w, nil)
	}
	return true
}

func ServerError(w http.ResponseWriter, suffix *string) {
	msg := "Internal server error"
	if suffix != nil {
		msg += ". " + *suffix
	}
	genericError(w, http.StatusInternalServerError, msg)
}

func UnauthorizedError(w http.ResponseWriter, suffix *string) {
	msg := "Unauthorized"
	if suffix != nil {
		msg += ". " + *suffix
	}
	genericError(w, http.StatusUnauthorized, msg)
}

func ForbiddenError(w http.ResponseWriter, suffix *string) {
	msg := "Forbidden"
	if suffix != nil {
		msg += ". " + *suffix
	}
	genericError(w, http.StatusForbidden, msg)
}

func InvalidTokenError(w http.ResponseWriter) {
	s := "InvalidToken"
	InputError(w, &s)
}

func ExpiredTokenError(w http.ResponseWriter) {
	// WARN: See https://github.com/bluesky-social/atproto/discussions/3319
	writeJSON(w, http.StatusBadRequest, map[string]string{
		"error":   "ExpiredToken",
		"message": "*",
	})
}

func genericError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{
		"error": msg,
	})
}

func RandomVarchar(length int) string {
	b := make([]rune, length)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func RandomHex(n int) (string, error) {
	bytes := make([]byte, n)
	if _, err := crand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func RandomBytes(n int) []byte {
	bs := make([]byte, n)
	_, _ = crand.Read(bs)
	return bs
}

func ParseJWKFromBytes(b []byte) (jwk.Key, error) {
	return jwk.ParseKey(b)
}

func OauthParseHtu(htu string) (string, error) {
	u, err := url.Parse(htu)
	if err != nil {
		return "", errors.New("`htu` is not a valid URL")
	}

	if u.User != nil {
		_, containsPass := u.User.Password()
		if u.User.Username() != "" || containsPass {
			return "", errors.New("`htu` must not contain credentials")
		}
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return "", errors.New("`htu` must be http or https")
	}

	return OauthNormalizeHtu(u), nil
}

func OauthNormalizeHtu(u *url.URL) string {
	return u.Scheme + "://" + u.Host + u.RawPath
}
