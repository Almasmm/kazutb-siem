package store

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	clickhousedriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/ingest"
)

//go:embed clickhouse_migrations/*.sql
var clickhouseMigrations embed.FS

type ClickHouse struct {
	conn clickhousedriver.Conn
}

type TelemetryMetrics struct {
	Events24h          int
	DetectionLatencyMS int
}

func OpenClickHouse(ctx context.Context, dsn string) (*ClickHouse, error) {
	if strings.TrimSpace(dsn) == "" {
		return nil, errors.New("KCSP_CLICKHOUSE_URL is required")
	}
	options, err := clickhouse.ParseDSN(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse ClickHouse configuration: %w", err)
	}
	options.MaxOpenConns = 20
	options.MaxIdleConns = 5
	options.ConnMaxLifetime = time.Hour
	conn, err := clickhouse.Open(options)
	if err != nil {
		return nil, fmt.Errorf("open ClickHouse: %w", err)
	}
	store := &ClickHouse{conn: conn}
	if err := store.Health(ctx); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("connect ClickHouse: %w", err)
	}
	if err := store.migrate(ctx); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return store, nil
}

func (c *ClickHouse) Health(ctx context.Context) error { return c.conn.Ping(ctx) }
func (c *ClickHouse) Close()                           { _ = c.conn.Close() }

func (c *ClickHouse) migrate(ctx context.Context) error {
	entries, err := fs.ReadDir(clickhouseMigrations, "clickhouse_migrations")
	if err != nil {
		return fmt.Errorf("read ClickHouse migrations: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		body, err := clickhouseMigrations.ReadFile("clickhouse_migrations/" + entry.Name())
		if err != nil {
			return fmt.Errorf("read ClickHouse migration %s: %w", entry.Name(), err)
		}
		for _, statement := range strings.Split(string(body), ";") {
			if statement = strings.TrimSpace(statement); statement != "" {
				if err := c.conn.Exec(ctx, statement); err != nil {
					return fmt.Errorf("apply ClickHouse migration %s: %w", entry.Name(), err)
				}
			}
		}
	}
	return nil
}

func (c *ClickHouse) PutRawEnvelope(ctx context.Context, envelope ingest.RawEnvelope) error {
	return c.conn.Exec(ctx, `INSERT INTO raw_events
		(tenant_id,event_id,message_id,collector_id,event_timestamp,received_at,format,content_type,schema_version,raw_hash,payload)
		VALUES (?,?,?,?,?,?,?,?,?,?,?)`, envelope.TenantID, envelope.EventID, envelope.MessageID, envelope.CollectorID,
		envelope.EventTimestamp, envelope.ReceivedAt, envelope.Format, envelope.ContentType, envelope.SchemaVersion,
		envelope.RawHash, string(envelope.PayloadBytes()))
}

// RawEnvelopeCount exposes the durable raw-ingest invariant for operations and
// integration checks without leaking the ClickHouse driver outside the store.
func (c *ClickHouse) RawEnvelopeCount(ctx context.Context, tenantID, eventID string) (int, error) {
	var count uint64
	err := c.conn.QueryRow(ctx, `
		SELECT count()
		FROM raw_events
		WHERE tenant_id = ? AND event_id = ?
	`, tenantID, eventID).Scan(&count)
	return int(count), err
}

func (c *ClickHouse) PutEvent(ctx context.Context, event core.CanonicalEvent) (core.CanonicalEvent, bool, error) {
	existing, err := c.GetEvent(ctx, event.TenantID, event.ID)
	if err == nil {
		return existing, true, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return core.CanonicalEvent{}, false, err
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return core.CanonicalEvent{}, false, fmt.Errorf("encode normalized event: %w", err)
	}
	version := uint64(event.IngestTime.UnixNano())
	if err := c.conn.Exec(ctx, `INSERT INTO normalized_events
		(tenant_id,event_id,event_time,ingest_time,category,severity,source_vendor,source_product,source_type,user_name,
		 device_hostname,src_ip,dst_ip,raw_hash,payload,version) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		event.TenantID, event.ID, event.EventTime, event.IngestTime, event.Category, event.Severity,
		event.Source.Vendor, event.Source.Product, event.Source.Type, event.User.Name, event.Device.Hostname,
		event.SrcEndpoint.IP, event.DstEndpoint.IP, event.Raw.Hash, string(payload), version); err != nil {
		return core.CanonicalEvent{}, false, fmt.Errorf("insert normalized event: %w", err)
	}
	return event, false, nil
}

func (c *ClickHouse) GetEvent(ctx context.Context, tenantID, eventID string) (core.CanonicalEvent, error) {
	var payload string
	err := c.conn.QueryRow(ctx, `SELECT payload FROM normalized_events FINAL
		WHERE tenant_id=? AND event_id=? ORDER BY version DESC LIMIT 1`, tenantID, eventID).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) {
		return core.CanonicalEvent{}, ErrNotFound
	}
	if err != nil {
		return core.CanonicalEvent{}, fmt.Errorf("get ClickHouse event: %w", err)
	}
	var event core.CanonicalEvent
	if err := json.Unmarshal([]byte(payload), &event); err != nil {
		return core.CanonicalEvent{}, fmt.Errorf("decode ClickHouse event: %w", err)
	}
	return event, nil
}

func (c *ClickHouse) ListEvents(ctx context.Context, tenantID string, filter EventFilter) ([]core.CanonicalEvent, error) {
	where := []string{"tenant_id=?"}
	args := []interface{}{tenantID}
	if filter.Category != "" {
		where = append(where, "lower(category)=lower(?)")
		args = append(args, filter.Category)
	}
	if filter.Severity > 0 {
		where = append(where, "severity=?")
		args = append(args, filter.Severity)
	}
	if query := strings.TrimSpace(filter.Query); query != "" {
		where = append(where, "positionCaseInsensitiveUTF8(payload, ?) > 0")
		args = append(args, query)
	}
	args = append(args, normalizedLimit(filter.Limit))
	query := "SELECT payload FROM normalized_events FINAL WHERE " + strings.Join(where, " AND ") + " ORDER BY event_time DESC LIMIT ?"
	rows, err := c.conn.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list ClickHouse events: %w", err)
	}
	defer rows.Close()
	result := []core.CanonicalEvent{}
	for rows.Next() {
		var payload string
		var event core.CanonicalEvent
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(payload), &event); err != nil {
			return nil, fmt.Errorf("decode ClickHouse event: %w", err)
		}
		result = append(result, event)
	}
	return result, rows.Err()
}

func (c *ClickHouse) PutFinding(ctx context.Context, finding core.Finding) error {
	payload, err := json.Marshal(finding)
	if err != nil {
		return fmt.Errorf("encode ClickHouse finding: %w", err)
	}
	return c.conn.Exec(ctx, `INSERT INTO findings
		(tenant_id,finding_id,event_id,rule_id,severity,risk_score,created_at,payload,version) VALUES (?,?,?,?,?,?,?,?,?)`,
		finding.TenantID, finding.ID, finding.EventID, finding.Rule.ID, finding.Severity, finding.RiskScore,
		finding.CreatedAt, string(payload), uint64(finding.CreatedAt.UnixNano()))
}

func (c *ClickHouse) ListFindings(ctx context.Context, tenantID, eventID string, limit int) ([]core.Finding, error) {
	where := "tenant_id=?"
	args := []interface{}{tenantID}
	if eventID != "" {
		where += " AND event_id=?"
		args = append(args, eventID)
	}
	args = append(args, normalizedLimit(limit))
	rows, err := c.conn.Query(ctx, "SELECT payload FROM findings FINAL WHERE "+where+" ORDER BY created_at DESC LIMIT ?", args...)
	if err != nil {
		return nil, fmt.Errorf("list ClickHouse findings: %w", err)
	}
	defer rows.Close()
	result := []core.Finding{}
	for rows.Next() {
		var payload string
		var finding core.Finding
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(payload), &finding); err != nil {
			return nil, fmt.Errorf("decode ClickHouse finding: %w", err)
		}
		result = append(result, finding)
	}
	return result, rows.Err()
}

func (c *ClickHouse) Metrics(ctx context.Context, tenantID string) (TelemetryMetrics, error) {
	var metrics TelemetryMetrics
	if err := c.conn.QueryRow(ctx, `SELECT count() FROM normalized_events FINAL
		WHERE tenant_id=? AND ingest_time >= now() - INTERVAL 24 HOUR`, tenantID).Scan(&metrics.Events24h); err != nil {
		return metrics, fmt.Errorf("count ClickHouse events: %w", err)
	}
	var latency float64
	if err := c.conn.QueryRow(ctx, `SELECT ifNull(avg(dateDiff('millisecond', e.ingest_time, f.created_at)),0)
		FROM findings FINAL AS f INNER JOIN normalized_events FINAL AS e
		ON f.tenant_id=e.tenant_id AND f.event_id=e.event_id WHERE f.tenant_id=?`, tenantID).Scan(&latency); err != nil {
		return metrics, fmt.Errorf("measure ClickHouse detection latency: %w", err)
	}
	metrics.DetectionLatencyMS = int(latency)
	return metrics, nil
}

func (c *ClickHouse) ResetTenant(ctx context.Context, tenantID string) error {
	for _, table := range []string{"raw_events", "findings", "normalized_events"} {
		if err := c.conn.Exec(ctx, "ALTER TABLE "+table+" DELETE WHERE tenant_id=? SETTINGS mutations_sync=1", tenantID); err != nil {
			return fmt.Errorf("reset ClickHouse table %s: %w", table, err)
		}
	}
	return nil
}
