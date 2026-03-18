package helpers

import (
	"net/http"
)

// RequestHost determines the correct host for the given HTTP request,
// prioritizing the X-Forwarded-Host header.
func RequestHost(r *http.Request) string {
	if fwdHost := r.Header.Get("X-Forwarded-Host"); fwdHost != "" {
		return fwdHost
	}
	return r.Host
}

// RequestScheme determines the correct scheme for the given HTTP request,
// prioritizing the X-Forwarded-Proto header.
func RequestScheme(r *http.Request) string {
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		return proto
	}
	if r.TLS == nil {
		return "http"
	}
	return "https"
}

// RequestURL reconstructs the full URL from an HTTP request.
func RequestURL(r *http.Request) string {
	return RequestScheme(r) + "://" + RequestHost(r) + r.URL.String()
}
