package entitygraph

import (
	"context"
	"errors"
	"strings"

	"github.com/kcsp/platform/internal/core"
)

var ErrNotAsset = errors.New("entity is not an asset")

type Repository interface {
	ListEntities(context.Context, string, core.EntityFilter) ([]core.SecurityEntity, error)
	GetEntity(context.Context, string, string) (core.SecurityEntity, error)
	GetEntityGraph(context.Context, string, string, int, int) (core.EntityGraph, error)
}

type Service struct{ store Repository }

func NewService(repository Repository) *Service { return &Service{store: repository} }

func (s *Service) Entities(ctx context.Context, tenantID string, filter core.EntityFilter) ([]core.SecurityEntity, error) {
	filter.Query = strings.TrimSpace(filter.Query)
	if filter.MinimumRisk < 0 {
		filter.MinimumRisk = 0
	}
	if filter.MinimumRisk > 100 {
		filter.MinimumRisk = 100
	}
	return s.store.ListEntities(ctx, tenantID, filter)
}

func (s *Service) Assets(ctx context.Context, tenantID string, filter core.EntityFilter) ([]core.SecurityEntity, error) {
	filter.Type = core.EntityTypeDevice
	return s.Entities(ctx, tenantID, filter)
}

func (s *Service) Entity(ctx context.Context, tenantID, entityID string) (core.SecurityEntity, error) {
	return s.store.GetEntity(ctx, tenantID, strings.TrimSpace(entityID))
}

func (s *Service) Asset(ctx context.Context, tenantID, entityID string) (core.SecurityEntity, error) {
	entity, err := s.Entity(ctx, tenantID, entityID)
	if err != nil {
		return core.SecurityEntity{}, err
	}
	if entity.Type != core.EntityTypeDevice && entity.Type != core.EntityTypeServer {
		return core.SecurityEntity{}, ErrNotAsset
	}
	return entity, nil
}

func (s *Service) Graph(ctx context.Context, tenantID, entityID string, depth, limit int) (core.EntityGraph, error) {
	if depth < 1 {
		depth = 1
	}
	if depth > 3 {
		depth = 3
	}
	return s.store.GetEntityGraph(ctx, tenantID, strings.TrimSpace(entityID), depth, limit)
}
