package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/kcsp/platform/internal/core"
)

type CollectorRegistry interface {
	RegisterCollector(context.Context, core.Collector) (core.Collector, error)
	ListCollectors(context.Context, string) ([]core.Collector, error)
	CollectorBySubject(context.Context, string, string) (core.Collector, error)
	HeartbeatCollector(context.Context, string, string, core.CollectorHeartbeat, string) (core.Collector, error)
	SetCollectorState(context.Context, string, string, string) (core.Collector, error)
}

func (p *Postgres) RegisterCollector(ctx context.Context, collector core.Collector) (core.Collector, error) {
	collector.ID = strings.TrimSpace(collector.ID)
	collector.TenantID = strings.TrimSpace(collector.TenantID)
	collector.Name = strings.TrimSpace(collector.Name)
	collector.Type = strings.TrimSpace(collector.Type)
	collector.AuthSubject = strings.TrimSpace(collector.AuthSubject)
	if collector.ID == "" || collector.TenantID == "" || collector.Name == "" || collector.Type == "" || collector.AuthSubject == "" {
		return core.Collector{}, errors.New("collector ID, tenant, name, type and auth subject are required")
	}
	if len(collector.ID) > 128 || len(collector.AuthSubject) > 256 || len(collector.Name) > 256 || len(collector.Type) > 64 {
		return core.Collector{}, errors.New("collector identity field exceeds allowed length")
	}
	collector.State = "ACTIVE"
	collector.Capabilities = normalizedCapabilities(collector.Capabilities)
	if collector.HealthMetadata == nil {
		collector.HealthMetadata = map[string]interface{}{}
	}
	metadata, err := json.Marshal(collector.HealthMetadata)
	if err != nil {
		return core.Collector{}, fmt.Errorf("encode collector metadata: %w", err)
	}
	now := time.Now().UTC()
	row := p.pool.QueryRow(ctx, `INSERT INTO collectors
		(tenant_id,collector_id,name,collector_type,auth_subject,state,capabilities,version,observed_ip,health_metadata,last_seen_at,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$12)
		RETURNING tenant_id,collector_id,name,collector_type,auth_subject,state,capabilities,version,observed_ip,health_metadata,last_seen_at,created_at,updated_at`,
		collector.TenantID, collector.ID, collector.Name, collector.Type, collector.AuthSubject, collector.State,
		collector.Capabilities, collector.Version, collector.ObservedIP, metadata, collector.LastSeenAt, now)
	created, err := scanCollector(row)
	if err != nil {
		var postgresError *pgconn.PgError
		if errors.As(err, &postgresError) && postgresError.Code == "23505" {
			return core.Collector{}, fmt.Errorf("%w: collector ID or auth subject is already registered", ErrAlreadyExists)
		}
		return core.Collector{}, fmt.Errorf("register collector: %w", err)
	}
	return created, nil
}

func (p *Postgres) ListCollectors(ctx context.Context, tenantID string) ([]core.Collector, error) {
	rows, err := p.pool.Query(ctx, `SELECT tenant_id,collector_id,name,collector_type,auth_subject,state,capabilities,
		version,observed_ip,health_metadata,last_seen_at,created_at,updated_at
		FROM collectors WHERE tenant_id=$1 ORDER BY name,collector_id`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list collectors: %w", err)
	}
	defer rows.Close()
	collectors := []core.Collector{}
	for rows.Next() {
		collector, err := scanCollector(rows)
		if err != nil {
			return nil, fmt.Errorf("scan collector: %w", err)
		}
		collectors = append(collectors, collector)
	}
	return collectors, rows.Err()
}

func (p *Postgres) CollectorBySubject(ctx context.Context, tenantID, subject string) (core.Collector, error) {
	collector, err := scanCollector(p.pool.QueryRow(ctx, `SELECT tenant_id,collector_id,name,collector_type,auth_subject,state,capabilities,
		version,observed_ip,health_metadata,last_seen_at,created_at,updated_at
		FROM collectors WHERE tenant_id=$1 AND auth_subject=$2`, tenantID, subject))
	if errors.Is(err, pgx.ErrNoRows) {
		return core.Collector{}, ErrNotFound
	}
	if err != nil {
		return core.Collector{}, fmt.Errorf("find collector subject: %w", err)
	}
	return collector, nil
}

func (p *Postgres) HeartbeatCollector(ctx context.Context, tenantID, subject string, heartbeat core.CollectorHeartbeat, observedIP string) (core.Collector, error) {
	if len(heartbeat.Version) > 128 || len(observedIP) > 128 {
		return core.Collector{}, errors.New("collector heartbeat field exceeds allowed length")
	}
	if heartbeat.Metadata == nil {
		heartbeat.Metadata = map[string]interface{}{}
	}
	metadata, err := json.Marshal(heartbeat.Metadata)
	if err != nil {
		return core.Collector{}, fmt.Errorf("encode collector heartbeat: %w", err)
	}
	now := time.Now().UTC()
	collector, err := scanCollector(p.pool.QueryRow(ctx, `UPDATE collectors SET version=$3,observed_ip=$4,health_metadata=$5,
		last_seen_at=$6,updated_at=$6 WHERE tenant_id=$1 AND auth_subject=$2 AND state='ACTIVE'
		RETURNING tenant_id,collector_id,name,collector_type,auth_subject,state,capabilities,version,observed_ip,
		health_metadata,last_seen_at,created_at,updated_at`, tenantID, subject, strings.TrimSpace(heartbeat.Version), observedIP, metadata, now))
	if errors.Is(err, pgx.ErrNoRows) {
		return core.Collector{}, ErrNotFound
	}
	if err != nil {
		return core.Collector{}, fmt.Errorf("update collector heartbeat: %w", err)
	}
	return collector, nil
}

func (p *Postgres) SetCollectorState(ctx context.Context, tenantID, collectorID, state string) (core.Collector, error) {
	state = strings.ToUpper(strings.TrimSpace(state))
	if state != "ACTIVE" && state != "REVOKED" {
		return core.Collector{}, errors.New("collector state must be ACTIVE or REVOKED")
	}
	collector, err := scanCollector(p.pool.QueryRow(ctx, `UPDATE collectors SET state=$3,updated_at=$4
		WHERE tenant_id=$1 AND collector_id=$2
		RETURNING tenant_id,collector_id,name,collector_type,auth_subject,state,capabilities,version,observed_ip,
		health_metadata,last_seen_at,created_at,updated_at`, tenantID, collectorID, state, time.Now().UTC()))
	if errors.Is(err, pgx.ErrNoRows) {
		return core.Collector{}, ErrNotFound
	}
	if err != nil {
		return core.Collector{}, fmt.Errorf("set collector state: %w", err)
	}
	return collector, nil
}

type collectorScanner interface {
	Scan(...interface{}) error
}

func scanCollector(scanner collectorScanner) (core.Collector, error) {
	var collector core.Collector
	var metadata []byte
	if err := scanner.Scan(
		&collector.TenantID, &collector.ID, &collector.Name, &collector.Type, &collector.AuthSubject, &collector.State,
		&collector.Capabilities, &collector.Version, &collector.ObservedIP, &metadata, &collector.LastSeenAt,
		&collector.CreatedAt, &collector.UpdatedAt,
	); err != nil {
		return core.Collector{}, err
	}
	if len(metadata) > 0 {
		if err := json.Unmarshal(metadata, &collector.HealthMetadata); err != nil {
			return core.Collector{}, err
		}
	}
	collector.Health = collectorHealth(collector, time.Now().UTC())
	return collector, nil
}

func collectorHealth(collector core.Collector, now time.Time) string {
	if collector.State == "REVOKED" {
		return "REVOKED"
	}
	if collector.LastSeenAt == nil {
		return "NEVER_SEEN"
	}
	if now.Sub(collector.LastSeenAt.UTC()) > 2*time.Minute {
		return "OFFLINE"
	}
	return "ONLINE"
}

func normalizedCapabilities(values []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" || len(value) > 64 || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	return result
}
