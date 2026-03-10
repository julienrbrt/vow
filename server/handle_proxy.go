package server

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"pkg.rbrt.fr/vow/internal/helpers"
	"pkg.rbrt.fr/vow/models"
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
		// When proxying app.bsky.feed.getFeed the token is issued for the
		// underlying feed generator. The getFeed handler sets the desired lxm
		// and aud on the context so they propagate here.
		lxm, proxyTokenLxmExists := getContextValue[string](r, contextKeyProxyTokenLxm)
		if !proxyTokenLxmExists || lxm == "" {
			lxm = pts[2]
		}
		aud, proxyTokenAudExists := getContextValue[string](r, contextKeyProxyTokenAud)
		if !proxyTokenAudExists || aud == "" {
			aud = svcDid
		}

		// exp=0 tells signServiceAuthJWT to use the default lifetime and
		// cache the resulting token so repeated proxy calls for the same
		// (aud, lxm) pair reuse it instead of prompting the wallet each time.
		token, err := s.signServiceAuthJWT(r.Context(), repo, aud, lxm, 0)
		if err != nil {
			switch err {
			case ErrSignerNotConnected:
				helpers.InputError(w, new("SignerNotConnected"))
			case ErrSignerRejected:
				helpers.InputError(w, new("SignatureRejected"))
			case ErrSignerTimeout:
				helpers.InputError(w, new("SignerTimeout"))
			default:
				logger.Error("error signing proxy JWT", "error", err)
				helpers.ServerError(w, nil)
			}
			return
		}

		req.Header.Set("authorization", "Bearer "+token)
	} else {
		req.Header.Del("authorization")
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		helpers.ServerError(w, nil)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	for k, v := range resp.Header {
		w.Header().Set(k, strings.Join(v, ","))
	}
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		logger.Error("failed to copy response body", "error", err)
	}
}
