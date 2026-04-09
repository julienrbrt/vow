package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"pkg.rbrt.fr/vow/models"
)

type Session struct {
	AccessToken  string
	RefreshToken string
}

func (s *Server) signInternalJWT(claims map[string]any) (string, error) {
	header := map[string]string{
		"alg": "ES256",
		"typ": "JWT",
	}
	hj, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshaling header: %w", err)
	}
	encheader := base64.RawURLEncoding.EncodeToString(hj)

	pj, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshaling payload: %w", err)
	}
	encpayload := base64.RawURLEncoding.EncodeToString(pj)

	signingString := fmt.Sprintf("%s.%s", encheader, encpayload)

	sig, err := s.privateKeyATP.HashAndSign([]byte(signingString))
	if err != nil {
		return "", fmt.Errorf("signing failed: %w", err)
	}

	encsig := strings.TrimRight(base64.RawURLEncoding.EncodeToString(sig), "=")
	return signingString + "." + encsig, nil
}

func (s *Server) createSession(ctx context.Context, repo *models.Repo) (*Session, error) {
	now := time.Now()
	accexp := now.Add(3 * time.Hour)
	refexp := now.Add(7 * 24 * time.Hour)
	jti := uuid.NewString()

	accessClaims := map[string]any{
		"scope": "com.atproto.access",
		"aud":   s.config.Did,
		"sub":   repo.Did,
		"iat":   now.UTC().Unix(),
		"exp":   accexp.UTC().Unix(),
		"jti":   jti,
	}

	accessString, err := s.signInternalJWT(accessClaims)
	if err != nil {
		return nil, err
	}

	refreshClaims := map[string]any{
		"scope": "com.atproto.refresh",
		"aud":   s.config.Did,
		"sub":   repo.Did,
		"iat":   now.UTC().Unix(),
		"exp":   refexp.UTC().Unix(),
		"jti":   jti,
	}

	refreshString, err := s.signInternalJWT(refreshClaims)
	if err != nil {
		return nil, err
	}

	if err := s.db.Create(ctx, &models.Token{
		Token:        accessString,
		Did:          repo.Did,
		RefreshToken: refreshString,
		CreatedAt:    now,
		ExpiresAt:    accexp,
	}, nil).Error; err != nil {
		return nil, err
	}

	if err := s.db.Create(ctx, &models.RefreshToken{
		Token:     refreshString,
		Did:       repo.Did,
		CreatedAt: now,
		ExpiresAt: refexp,
	}, nil).Error; err != nil {
		return nil, err
	}

	return &Session{
		AccessToken:  accessString,
		RefreshToken: refreshString,
	}, nil
}
