package provider

import (
	"net/http"
)

func (p *Provider) BaseMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("cache-control", "no-store")
		w.Header().Set("pragma", "no-cache")

		nonce := p.NextNonce()
		if nonce != "" {
			w.Header().Set("DPoP-Nonce", nonce)
			w.Header().Add("access-control-expose-headers", "DPoP-Nonce")
		}

		next.ServeHTTP(w, r)
	})
}
