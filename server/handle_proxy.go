package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"pkg.rbrt.fr/vow/internal/helpers"
	"pkg.rbrt.fr/vow/models"
	secp256k1secec "gitlab.com/yawning/secp256k1-voi/secec"
)

func (s *Server) getAtprotoProxyEndpointFromRequest(r *http.Request) (string, string, error) {
	svc := r.Header.Get("atproto-proxy")
	if svc == "" && s.config.FallbackProxy != "" {
		svc = s.config.FallbackProxy
	}

	svcPts := strings.Split(svc, "#")
	if len(svcPts) != 2 {
		return "", "", fmt.Errorf("invalid service header")
	}

	svcDid := svcPts[0]
	svcId := "#" + svcPts[1]

	doc, err := s.passport.FetchDoc(r.Context(), svcDid)
	if err != nil {
		return "", "", err
	}

	var endpoint string
	for _, s := range doc.Service {
		if s.Id == svcId {
			endpoint = s.ServiceEndpoint
		}
	}

	return endpoint, svcDid, nil
}

func (s *Server) handleProxy(w http.ResponseWriter, r *http.Request) {
	logger := s.logger.With("handler", "handleProxy")

	repo, isAuthed := getContextValue[*models.RepoActor](r, contextKeyRepo)

	pts := strings.Split(r.URL.Path, "/")
	if len(pts) != 3 {
		helpers.ServerError(w, nil)
		return
	}

	endpoint, svcDid, err := s.getAtprotoProxyEndpointFromRequest(r)
	if err != nil {
		logger.Error("could not get atproto proxy", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	requrl := *r.URL
	requrl.Host = strings.TrimPrefix(endpoint, "https://")
	requrl.Scheme = "https"

	var body io.Reader
	if r.Method != http.MethodGet {
		body = r.Body
	}

	req, err := http.NewRequest(r.Method, requrl.String(), body)
	if err != nil {
		helpers.ServerError(w, nil)
		return
	}

	req.Header = r.Header.Clone()

	if isAuthed {
		// this is a little dumb. i should probably figure out a better way to do this, and use
		// a single way of creating/signing jwts throughout the pds. kinda limited here because
		// im using the atproto crypto lib for this though. will come back to it

		header := map[string]string{
			"alg": "ES256K",
			"crv": "secp256k1",
			"typ": "JWT",
		}
		hj, err := json.Marshal(header)
		if err != nil {
			logger.Error("error marshaling header", "error", err)
			helpers.ServerError(w, nil)
			return
		}

		encheader := strings.TrimRight(base64.RawURLEncoding.EncodeToString(hj), "=")

		// When proxying app.bsky.feed.getFeed the token is actually issued for the
		// underlying feed generator and the app view passes it on. This allows the
		// getFeed implementation to pass in the desired lxm and aud for the token
		// and then just delegate to the general proxying logic
		lxm, proxyTokenLxmExists := getContextValue[string](r, contextKeyProxyTokenLxm)
		if !proxyTokenLxmExists || lxm == "" {
			lxm = pts[2]
		}
		aud, proxyTokenAudExists := getContextValue[string](r, contextKeyProxyTokenAud)
		if !proxyTokenAudExists || aud == "" {
			aud = svcDid
		}

		payload := map[string]any{
			"iss": repo.Repo.Did,
			"aud": aud,
			"lxm": lxm,
			"jti": uuid.NewString(),
			"exp": time.Now().Add(1 * time.Minute).UTC().Unix(),
		}
		pj, err := json.Marshal(payload)
		if err != nil {
			logger.Error("error marshaling payload", "error", err)
			helpers.ServerError(w, nil)
			return
		}

		encpayload := strings.TrimRight(base64.RawURLEncoding.EncodeToString(pj), "=")

		input := fmt.Sprintf("%s.%s", encheader, encpayload)
		hash := sha256.Sum256([]byte(input))

		sk, err := secp256k1secec.NewPrivateKey(repo.SigningKey)
		if err != nil {
			logger.Error("can't load private key", "error", err)
			helpers.ServerError(w, nil)
			return
		}

		R, S, _, err := sk.SignRaw(rand.Reader, hash[:])
		if err != nil {
			logger.Error("error signing", "error", err)
			helpers.ServerError(w, nil)
			return
		}

		rBytes := R.Bytes()
		sBytes := S.Bytes()

		rPadded := make([]byte, 32)
		sPadded := make([]byte, 32)
		copy(rPadded[32-len(rBytes):], rBytes)
		copy(sPadded[32-len(sBytes):], sBytes)

		rawsig := append(rPadded, sPadded...)
		encsig := strings.TrimRight(base64.RawURLEncoding.EncodeToString(rawsig), "=")
		token := fmt.Sprintf("%s.%s", input, encsig)

		req.Header.Set("authorization", "Bearer "+token)
	} else {
		req.Header.Del("authorization")
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		helpers.ServerError(w, nil)
		return
	}
	defer resp.Body.Close()

	for k, v := range resp.Header {
		w.Header().Set(k, strings.Join(v, ","))
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}
