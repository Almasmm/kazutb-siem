package store

import (
	"context"
	"time"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/entitygraph"
)

func (h *Hybrid) ObserveEntityEvent(ctx context.Context, event core.CanonicalEvent) error {
	projection := entitygraph.Project(event)
	if err := h.control.observeEntityProjection(ctx, event, projection); err != nil {
		return err
	}
	policy, err := h.cachedRetentionPolicy(ctx, event.TenantID)
	if err != nil {
		return err
	}
	return h.telemetry.PutEntityProjectionWithExpiry(ctx, event, projection, event.EventTime.Add(time.Duration(policy.NormalizedDays)*24*time.Hour))
}

func (h *Hybrid) ListEntities(ctx context.Context, tenantID string, filter core.EntityFilter) ([]core.SecurityEntity, error) {
	return h.control.ListEntities(ctx, tenantID, filter)
}

func (h *Hybrid) GetEntity(ctx context.Context, tenantID, entityID string) (core.SecurityEntity, error) {
	return h.control.GetEntity(ctx, tenantID, entityID)
}

func (h *Hybrid) GetEntityGraph(ctx context.Context, tenantID, entityID string, depth, limit int) (core.EntityGraph, error) {
	return h.control.GetEntityGraph(ctx, tenantID, entityID, depth, limit)
}
