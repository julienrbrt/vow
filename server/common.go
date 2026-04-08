package server

import (
	"context"
	"strings"

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

func (s *Server) getRepoActor(ctx context.Context, where, arg string) (*models.RepoActor, error) {
	var repo models.RepoActor
	if err := s.db.Raw(ctx, `
		SELECT r.*, a.handle
		FROM repos r
		LEFT JOIN actors a ON r.did = a.did
		WHERE `+where, nil, arg).Scan(&repo).Error; err != nil {
		return nil, err
	}
	if repo.Repo.Did == "" {
		return nil, gorm.ErrRecordNotFound
	}
	return &repo, nil
}

func (s *Server) getRepoActorByEmail(ctx context.Context, email string) (*models.RepoActor, error) {
	return s.getRepoActor(ctx, "r.email = ?", email)
}

func (s *Server) getRepoActorByDid(ctx context.Context, did string) (*models.RepoActor, error) {
	return s.getRepoActor(ctx, "r.did = ?", did)
}

func (s *Server) getRepoActorByIdentifier(ctx context.Context, identifier string) (*models.RepoActor, error) {
	switch {
	case strings.HasPrefix(identifier, "did:"):
		return s.getRepoActorByDid(ctx, identifier)
	case strings.Contains(identifier, "@"):
		return s.getRepoActor(ctx, "r.email = ?", identifier)
	default:
		return s.getRepoActor(ctx, "a.handle = ?", identifier)
	}
}
