package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/kcsp/platform/internal/core"
)

func (p *Postgres) ReplayDetectionEvents(ctx context.Context, tenantID string, start, end time.Time, limit int) ([]core.CanonicalEvent, error) {
	rows, err := p.pool.Query(ctx, `SELECT payload FROM security_events
		WHERE tenant_id=$1 AND event_time >= $2 AND event_time < $3 ORDER BY event_time,event_id LIMIT $4`, tenantID, start, end, limit)
	if err != nil {
		return nil, fmt.Errorf("query PostgreSQL replay events: %w", err)
	}
	defer rows.Close()
	return scanReplayEvents(rows)
}

func (c *ClickHouse) ReplayDetectionEvents(ctx context.Context, tenantID string, start, end time.Time, limit int) ([]core.CanonicalEvent, error) {
	rows, err := c.conn.Query(ctx, `SELECT payload FROM normalized_events FINAL
		WHERE tenant_id=? AND event_time >= ? AND event_time < ? ORDER BY event_time,event_id LIMIT ?`, tenantID, start, end, limit)
	if err != nil {
		return nil, fmt.Errorf("query ClickHouse replay events: %w", err)
	}
	defer rows.Close()
	events := []core.CanonicalEvent{}
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		var event core.CanonicalEvent
		if err := json.Unmarshal([]byte(payload), &event); err != nil {
			return nil, fmt.Errorf("decode ClickHouse replay event: %w", err)
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func (h *Hybrid) ReplayDetectionEvents(ctx context.Context, tenantID string, start, end time.Time, limit int) ([]core.CanonicalEvent, error) {
	return h.telemetry.ReplayDetectionEvents(ctx, tenantID, start, end, limit)
}

type replayRows interface {
	Next() bool
	Scan(...interface{}) error
	Err() error
}

func scanReplayEvents(rows replayRows) ([]core.CanonicalEvent, error) {
	events := []core.CanonicalEvent{}
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		var event core.CanonicalEvent
		if err := json.Unmarshal(payload, &event); err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}
