package server

import (
	"context"

	"gorm.io/gorm"
	"pkg.rbrt.fr/vow/models"
)

func (s *Server) getActorByHandle(ctx context.Context, handle string) (*models.Actor, error) {
	var actor models.Actor
	if err := s.db.First(ctx, &actor, models.Actor{Handle: handle}).Error; err != nil {
		return nil, err
	}
	if actor.Did == "" {
		return nil, gorm.ErrRecordNotFound
	}
	return &actor, nil
}

func (s *Server) getRepoByEmail(ctx context.Context, email string) (*models.Repo, error) {
	var repo models.Repo
	if err := s.db.First(ctx, &repo, models.Repo{Email: email}).Error; err != nil {
		return nil, err
	}
	if repo.Did == "" {
		return nil, gorm.ErrRecordNotFound
	}
	return &repo, nil
}

func (s *Server) getRepoActorByEmail(ctx context.Context, email string) (*models.RepoActor, error) {
	var repo models.RepoActor
	// Use explicit column selection to ensure proper mapping to embedded structs.
	if err := s.db.Raw(ctx, `
		SELECT
			r.did, r.created_at, r.email, r.email_confirmed_at, r.email_verification_code,
			r.email_verification_code_expires_at, r.email_update_code, r.email_update_code_expires_at,
			r.password_reset_code, r.password_reset_code_expires_at, r.plc_operation_code,
			r.plc_operation_code_expires_at, r.account_delete_code, r.account_delete_code_expires_at,
			r.password, r.auth_public_key, r.signing_public_key, r.credential_id, r.compat_mode,
			r.rev, r.root, r.preferences, r.deactivated,
			a.handle
		FROM repos r
		LEFT JOIN actors a ON r.did = a.did
		WHERE r.email = ?
	`, nil, email).Scan(&repo).Error; err != nil {
		return nil, err
	}
	if repo.Repo.Did == "" {
		return nil, gorm.ErrRecordNotFound
	}
	return &repo, nil
}

func (s *Server) getRepoActorByDid(ctx context.Context, did string) (*models.RepoActor, error) {
	var repo models.RepoActor
	// Use explicit column selection to ensure proper mapping to embedded structs.
	// The r.*, a.* pattern can cause issues with GORM's Scan when structs have
	// overlapping field names (both Repo and Actor have "Did").
	if err := s.db.Raw(ctx, `
		SELECT
			r.did, r.created_at, r.email, r.email_confirmed_at, r.email_verification_code,
			r.email_verification_code_expires_at, r.email_update_code, r.email_update_code_expires_at,
			r.password_reset_code, r.password_reset_code_expires_at, r.plc_operation_code,
			r.plc_operation_code_expires_at, r.account_delete_code, r.account_delete_code_expires_at,
			r.password, r.auth_public_key, r.signing_public_key, r.credential_id, r.compat_mode,
			r.rev, r.root, r.preferences, r.deactivated,
			a.handle
		FROM repos r
		LEFT JOIN actors a ON r.did = a.did
		WHERE r.did = ?
	`, nil, did).Scan(&repo).Error; err != nil {
		return nil, err
	}
	if repo.Repo.Did == "" {
		return nil, gorm.ErrRecordNotFound
	}
	return &repo, nil
}
