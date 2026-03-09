package server

import (
	"fmt"
	"net/http"
	"strings"

	"gorm.io/gorm"
	"pkg.rbrt.fr/vow/internal/helpers"
)

var (
	VowSupportedScopes = []string{
		"atproto",
		"transition:email",
		"transition:generic",
		"transition:chat.bsky",
	}
)

type OauthAuthorizationMetadata struct {
	Issuer                                     string   `json:"issuer"`
	RequestParameterSupported                  bool     `json:"request_parameter_supported"`
	RequestUriParameterSupported               bool     `json:"request_uri_parameter_supported"`
	RequireRequestUriRegistration              *bool    `json:"require_request_uri_registration,omitempty"`
	ScopesSupported                            []string `json:"scopes_supported"`
	SubjectTypesSupported                      []string `json:"subject_types_supported"`
	ResponseTypesSupported                     []string `json:"response_types_supported"`
	ResponseModesSupported                     []string `json:"response_modes_supported"`
	GrantTypesSupported                        []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported              []string `json:"code_challenge_methods_supported"`
	UILocalesSupported                         []string `json:"ui_locales_supported"`
	DisplayValuesSupported                     []string `json:"display_values_supported"`
	RequestObjectSigningAlgValuesSupported     []string `json:"request_object_signing_alg_values_supported"`
	AuthorizationResponseISSParameterSupported bool     `json:"authorization_response_iss_parameter_supported"`
	RequestObjectEncryptionAlgValuesSupported  []string `json:"request_object_encryption_alg_values_supported"`
	RequestObjectEncryptionEncValuesSupported  []string `json:"request_object_encryption_enc_values_supported"`
	JwksUri                                    string   `json:"jwks_uri"`
	AuthorizationEndpoint                      string   `json:"authorization_endpoint"`
	TokenEndpoint                              string   `json:"token_endpoint"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported"`
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported"`
	RevocationEndpoint                         string   `json:"revocation_endpoint"`
	IntrospectionEndpoint                      string   `json:"introspection_endpoint"`
	PushedAuthorizationRequestEndpoint         string   `json:"pushed_authorization_request_endpoint"`
	RequirePushedAuthorizationRequests         bool     `json:"require_pushed_authorization_requests"`
	DpopSigningAlgValuesSupported              []string `json:"dpop_signing_alg_values_supported"`
	ProtectedResources                         []string `json:"protected_resources"`
	ClientIDMetadataDocumentSupported          bool     `json:"client_id_metadata_document_supported"`
}

func (s *Server) handleWellKnown(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, 200, map[string]any{
		"@context": []string{
			"https://www.w3.org/ns/did/v1",
		},
		"id": s.config.Did,
		"service": []map[string]string{
			{
				"id":              "#atproto_pds",
				"type":            "AtprotoPersonalDataServer",
				"serviceEndpoint": "https://" + s.config.Hostname,
			},
		},
	})
}

func (s *Server) handleAtprotoDid(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := s.logger.With("name", "handleAtprotoDid")

	host := r.Host
	if host == "" {
		helpers.InputError(w, new("Invalid handle."))
		return
	}

	host = strings.Split(host, ":")[0]
	host = strings.ToLower(strings.TrimSpace(host))

	if host == s.config.Hostname {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = fmt.Fprint(w, s.config.Did)
		return
	}

	suffix := "." + s.config.Hostname
	if !strings.HasSuffix(host, suffix) {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	actor, err := s.getActorByHandle(ctx, host)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		logger.Error("error looking up actor by handle", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	_, _ = fmt.Fprint(w, actor.Did)
}

func (s *Server) handleOauthProtectedResource(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, 200, map[string]any{
		"resource": "https://" + s.config.Hostname,
		"authorization_servers": []string{
			"https://" + s.config.Hostname,
		},
		"scopes_supported":         []string{},
		"bearer_methods_supported": []string{"header"},
		"resource_documentation":   "https://atproto.com",
	})
}

func (s *Server) handleOauthAuthorizationServer(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, 200, OauthAuthorizationMetadata{
		Issuer:                                     "https://" + s.config.Hostname,
		RequestParameterSupported:                  true,
		RequestUriParameterSupported:               true,
		RequireRequestUriRegistration:              new(true),
		ScopesSupported:                            VowSupportedScopes,
		SubjectTypesSupported:                      []string{"public"},
		ResponseTypesSupported:                     []string{"code"},
		ResponseModesSupported:                     []string{"query", "fragment", "form_post"},
		GrantTypesSupported:                        []string{"authorization_code", "refresh_token"},
		CodeChallengeMethodsSupported:              []string{"S256"},
		UILocalesSupported:                         []string{"en-US"},
		DisplayValuesSupported:                     []string{"page", "popup", "touch"},
		RequestObjectSigningAlgValuesSupported:     []string{"ES256"},
		AuthorizationResponseISSParameterSupported: true,
		RequestObjectEncryptionAlgValuesSupported:  []string{},
		RequestObjectEncryptionEncValuesSupported:  []string{},
		JwksUri:                           fmt.Sprintf("https://%s/oauth/jwks", s.config.Hostname),
		AuthorizationEndpoint:             fmt.Sprintf("https://%s/oauth/authorize", s.config.Hostname),
		TokenEndpoint:                     fmt.Sprintf("https://%s/oauth/token", s.config.Hostname),
		TokenEndpointAuthMethodsSupported: []string{"none", "private_key_jwt"},
		TokenEndpointAuthSigningAlgValuesSupported: []string{"ES256"},
		RevocationEndpoint:                         fmt.Sprintf("https://%s/oauth/revoke", s.config.Hostname),
		IntrospectionEndpoint:                      fmt.Sprintf("https://%s/oauth/introspect", s.config.Hostname),
		PushedAuthorizationRequestEndpoint:         fmt.Sprintf("https://%s/oauth/par", s.config.Hostname),
		RequirePushedAuthorizationRequests:         true,
		DpopSigningAlgValuesSupported:              []string{"ES256"},
		ProtectedResources:                         []string{"https://" + s.config.Hostname},
		ClientIDMetadataDocumentSupported:          true,
	})
}
