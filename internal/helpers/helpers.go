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

// This will confirm to the regex in the application if 5 chars are used for each side of the -
// /^[A-Z2-7]{5}-[A-Z2-7]{5}$/
var letters = []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")

func writeJSON(w http.ResponseWriter, status int, v any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(v)
}

func InputError(w http.ResponseWriter, custom *string) error {
	msg := "InvalidRequest"
	if custom != nil {
		msg = *custom
	}
	return genericError(w, http.StatusBadRequest, msg)
}

func ServerError(w http.ResponseWriter, suffix *string) error {
	msg := "Internal server error"
	if suffix != nil {
		msg += ". " + *suffix
	}
	return genericError(w, http.StatusInternalServerError, msg)
}

func UnauthorizedError(w http.ResponseWriter, suffix *string) error {
	msg := "Unauthorized"
	if suffix != nil {
		msg += ". " + *suffix
	}
	return genericError(w, http.StatusUnauthorized, msg)
}

func ForbiddenError(w http.ResponseWriter, suffix *string) error {
	msg := "Forbidden"
	if suffix != nil {
		msg += ". " + *suffix
	}
	return genericError(w, http.StatusForbidden, msg)
}

func InvalidTokenError(w http.ResponseWriter) error {
	s := "InvalidToken"
	return InputError(w, &s)
}

func ExpiredTokenError(w http.ResponseWriter) error {
	// WARN: See https://github.com/bluesky-social/atproto/discussions/3319
	return writeJSON(w, http.StatusBadRequest, map[string]string{
		"error":   "ExpiredToken",
		"message": "*",
	})
}

func genericError(w http.ResponseWriter, code int, msg string) error {
	return writeJSON(w, code, map[string]string{
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
	crand.Read(bs)
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
