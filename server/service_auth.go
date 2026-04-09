package server

import (
	"context"
	"fmt"
	"strings"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	atproto_identity "github.com/bluesky-social/indigo/atproto/identity"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/golang-jwt/jwt/v4"
)

type ES256KSigningMethod struct {
	alg string
}

func (m *ES256KSigningMethod) Alg() string {
	return m.alg
}

func (m *ES256KSigningMethod) Verify(signingString string, signature string, key any) error {
	signatureBytes, err := jwt.DecodeSegment(signature) //nolint:staticcheck
	if err != nil {
		return err
	}
	k, ok := key.(atcrypto.PublicKey)
	if !ok {
		return fmt.Errorf("invalid key type for ES256K verification")
	}
	return k.HashAndVerifyLenient([]byte(signingString), signatureBytes)
}

func (m *ES256KSigningMethod) Sign(signingString string, key any) (string, error) {
	return "", fmt.Errorf("unimplemented")
}

func init() {
	ES256K := ES256KSigningMethod{alg: "ES256K"}
	jwt.RegisterSigningMethod(ES256K.Alg(), func() jwt.SigningMethod {
		return &ES256K
	})
}

func (s *Server) validateServiceAuth(ctx context.Context, rawToken string, nsid string) (string, error) {
	token := strings.TrimSpace(rawToken)

	parsedToken, err := jwt.ParseWithClaims(token, jwt.MapClaims{}, func(token *jwt.Token) (any, error) {
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			return nil, fmt.Errorf("invalid token claims")
		}
		iss, ok := claims["iss"].(string)
		if !ok {
			return nil, fmt.Errorf("missing iss claim in token")
		}
		did := syntax.DID(iss)
		didDoc, err := s.passport.FetchDoc(ctx, did.String())
		if err != nil {
			return nil, fmt.Errorf("unable to resolve did %s: %s", did, err)
		}

		verificationMethods := make([]atproto_identity.DocVerificationMethod, len(didDoc.VerificationMethods))
		for i, verificationMethod := range didDoc.VerificationMethods {
			verificationMethods[i] = atproto_identity.DocVerificationMethod{
				ID:                 verificationMethod.Id,
				Type:               verificationMethod.Type,
				PublicKeyMultibase: verificationMethod.PublicKeyMultibase,
				Controller:         verificationMethod.Controller,
			}
		}
		services := make([]atproto_identity.DocService, len(didDoc.Service))
		for i, service := range didDoc.Service {
			services[i] = atproto_identity.DocService{
				ID:              service.Id,
				Type:            service.Type,
				ServiceEndpoint: service.ServiceEndpoint,
			}
		}
		parsedIdentity := atproto_identity.ParseIdentity(&atproto_identity.DIDDocument{
			DID:                did,
			AlsoKnownAs:        didDoc.AlsoKnownAs,
			VerificationMethod: verificationMethods,
			Service:            services,
		})

		// In compat mode, the JWT is signed with #atproto, so verify with that key.
		// Otherwise, prefer #atproto_service when present (ref: https://github.com/bluesky-social/atproto/discussions/4739)
		var key atcrypto.PublicKey
		repo, err := s.getRepoActorByDid(ctx, did.String())
		if err == nil && repo.CompatMode {
			key, err = parsedIdentity.PublicKey() // use #atproto
		} else {
			key, err = parsedIdentity.GetPublicKey("atproto_service")
			if err != nil {
				key, err = parsedIdentity.PublicKey() // fallback to #atproto
			}
		}
		if err != nil {
			return nil, fmt.Errorf("signing key not found for did %s: %s", did, err)
		}
		return key, nil
	})
	if err != nil {
		return "", fmt.Errorf("invalid token: %s", err)
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("invalid token claims")
	}
	if claims["lxm"] != nsid {
		return "", fmt.Errorf("bad jwt lexicon method (\"lxm\"). must match: %s", nsid)
	}
	iss, ok := claims["iss"].(string)
	if !ok {
		return "", fmt.Errorf("missing iss claim in token")
	}
	return iss, nil
}
