package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/kcsp/platform/internal/core"
)

func (c *ClickHouse) PutEntityProjectionWithExpiry(ctx context.Context, event core.CanonicalEvent, projection core.EntityProjection, expiresAt time.Time) error {
	if expiresAt.IsZero() {
		expiresAt = event.EventTime.Add(DefaultNormalizedRetentionDays * 24 * time.Hour)
	}
	version := uint64(event.IngestTime.UnixNano())
	if version == 0 {
		version = uint64(time.Now().UnixNano())
	}
	if len(projection.Entities) > 0 {
		batch, err := c.conn.PrepareBatch(ctx, `INSERT INTO entity_observations
			(tenant_id,event_id,event_time,entity_id,entity_type,natural_key,display_name,role,payload,version,expires_at)`)
		if err != nil {
			return fmt.Errorf("prepare entity observation batch: %w", err)
		}
		for _, entity := range projection.Entities {
			payload, err := json.Marshal(entity)
			if err != nil {
				return fmt.Errorf("encode entity observation: %w", err)
			}
			if err := batch.Append(event.TenantID, event.ID, event.EventTime, entity.ID, string(entity.Type), entity.NaturalKey, entity.DisplayName, entity.Label, string(payload), version, expiresAt.UTC()); err != nil {
				return fmt.Errorf("append entity observation: %w", err)
			}
		}
		if err := batch.Send(); err != nil {
			return fmt.Errorf("insert entity observations: %w", err)
		}
	}
	if len(projection.Relations) > 0 {
		batch, err := c.conn.PrepareBatch(ctx, `INSERT INTO entity_relation_observations
			(tenant_id,event_id,event_time,relation_id,relation_type,source_entity_id,target_entity_id,payload,version,expires_at)`)
		if err != nil {
			return fmt.Errorf("prepare relation observation batch: %w", err)
		}
		for _, relation := range projection.Relations {
			payload, err := json.Marshal(relation)
			if err != nil {
				return fmt.Errorf("encode relation observation: %w", err)
			}
			if err := batch.Append(event.TenantID, event.ID, event.EventTime, relation.ID, relation.Type, relation.SourceEntityID, relation.TargetEntityID, string(payload), version, expiresAt.UTC()); err != nil {
				return fmt.Errorf("append relation observation: %w", err)
			}
		}
		if err := batch.Send(); err != nil {
			return fmt.Errorf("insert relation observations: %w", err)
		}
	}
	return nil
}
