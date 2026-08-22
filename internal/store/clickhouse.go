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
	"github.com/kcsp/platform/internal/hunt"
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
	return c.PutRawEnvelopeWithExpiry(ctx, envelope, envelope.ReceivedAt.Add(DefaultRawRetentionDays*24*time.Hour))
}

func (c *ClickHouse) PutRawEnvelopeWithExpiry(ctx context.Context, envelope ingest.RawEnvelope, expiresAt time.Time) error {
	if expiresAt.IsZero() {
		expiresAt = envelope.ReceivedAt.Add(DefaultRawRetentionDays * 24 * time.Hour)
	}
	return c.conn.Exec(ctx, `INSERT INTO raw_events
		(tenant_id,event_id,message_id,collector_id,event_timestamp,received_at,format,content_type,schema_version,raw_hash,payload,expires_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`, envelope.TenantID, envelope.EventID, envelope.MessageID, envelope.CollectorID,
		envelope.EventTimestamp, envelope.ReceivedAt, envelope.Format, envelope.ContentType, envelope.SchemaVersion,
		envelope.RawHash, string(envelope.PayloadBytes()), expiresAt.UTC())
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
	return c.PutEventWithExpiry(ctx, event, event.EventTime.Add(DefaultNormalizedRetentionDays*24*time.Hour))
}

func (c *ClickHouse) PutEventWithExpiry(ctx context.Context, event core.CanonicalEvent, expiresAt time.Time) (core.CanonicalEvent, bool, error) {
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
	if expiresAt.IsZero() {
		expiresAt = event.EventTime.Add(DefaultNormalizedRetentionDays * 24 * time.Hour)
	}
	if err := c.conn.Exec(ctx, `INSERT INTO normalized_events
		(tenant_id,event_id,event_time,ingest_time,category,severity,source_vendor,source_product,source_type,user_name,
		 device_hostname,src_ip,dst_ip,raw_hash,payload,version,expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		event.TenantID, event.ID, event.EventTime, event.IngestTime, event.Category, event.Severity,
		event.Source.Vendor, event.Source.Product, event.Source.Type, event.User.Name, event.Device.Hostname,
		event.SrcEndpoint.IP, event.DstEndpoint.IP, event.Raw.Hash, string(payload), version, expiresAt.UTC()); err != nil {
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

func (c *ClickHouse) HuntEvents(ctx context.Context, tenantID string, request core.HuntRequest) (core.HuntPage, error) {
	started := time.Now()
	normalized, err := hunt.Normalize(request, time.Now().UTC())
	if err != nil {
		return core.HuntPage{}, err
	}
	queryHash := hunt.QueryHash(normalized)
	cursor, err := hunt.DecodeCursor(normalized.Cursor)
	if err != nil {
		return core.HuntPage{}, err
	}
	if cursor.QueryHash != "" && cursor.QueryHash != queryHash {
		return core.HuntPage{}, fmt.Errorf("%w: cursor belongs to a different query", hunt.ErrInvalidQuery)
	}
	expression, expressionArgs, err := hunt.CompileExpression(normalized.Expression)
	if err != nil {
		return core.HuntPage{}, err
	}
	where := []string{"tenant_id=?", "event_time>=?", "event_time<?"}
	args := []interface{}{tenantID, normalized.Start, normalized.End}
	if expression != "" {
		where = append(where, "("+expression+")")
		args = append(args, expressionArgs...)
	}
	if !cursor.EventTime.IsZero() {
		where = append(where, "(event_time<? OR (event_time=? AND event_id<?))")
		args = append(args, cursor.EventTime, cursor.EventTime, cursor.EventID)
	}
	args = append(args, normalized.Limit+1)
	query := `SELECT payload,event_time,event_id FROM normalized_events FINAL WHERE ` + strings.Join(where, " AND ") +
		` ORDER BY event_time DESC,event_id DESC LIMIT ? SETTINGS max_execution_time=15,max_result_rows=1001,result_overflow_mode='break',max_threads=4`
	queryContext, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	rows, err := c.conn.Query(queryContext, query, args...)
	if err != nil {
		return core.HuntPage{}, fmt.Errorf("hunt ClickHouse events: %w", err)
	}
	defer rows.Close()
	items := []core.CanonicalEvent{}
	times := []time.Time{}
	ids := []string{}
	for rows.Next() {
		var payload, eventID string
		var eventTime time.Time
		if err := rows.Scan(&payload, &eventTime, &eventID); err != nil {
			return core.HuntPage{}, err
		}
		var event core.CanonicalEvent
		if err := json.Unmarshal([]byte(payload), &event); err != nil {
			return core.HuntPage{}, fmt.Errorf("decode hunted ClickHouse event: %w", err)
		}
		items = append(items, event)
		times = append(times, eventTime)
		ids = append(ids, eventID)
	}
	if err := rows.Err(); err != nil {
		return core.HuntPage{}, err
	}
	nextCursor := ""
	if len(items) > normalized.Limit {
		last := normalized.Limit - 1
		nextCursor = hunt.EncodeCursor(hunt.Cursor{EventTime: times[last].UTC(), EventID: ids[last], QueryHash: queryHash})
		items = items[:normalized.Limit]
	}
	return core.HuntPage{
		ExecutionID: core.NewID("hex"), QueryHash: queryHash, Start: normalized.Start, End: normalized.End,
		Items: items, Returned: len(items), NextCursor: nextCursor, DurationMicros: time.Since(started).Microseconds(), Partial: false,
	}, nil
}

func (c *ClickHouse) PutFinding(ctx context.Context, finding core.Finding) error {
	return c.PutFindingWithExpiry(ctx, finding, finding.CreatedAt.Add(DefaultFindingsRetentionDays*24*time.Hour))
}

func (c *ClickHouse) PutFindingWithExpiry(ctx context.Context, finding core.Finding, expiresAt time.Time) error {
	payload, err := json.Marshal(finding)
	if err != nil {
		return fmt.Errorf("encode ClickHouse finding: %w", err)
	}
	if expiresAt.IsZero() {
		expiresAt = finding.CreatedAt.Add(DefaultFindingsRetentionDays * 24 * time.Hour)
	}
	return c.conn.Exec(ctx, `INSERT INTO findings
		(tenant_id,finding_id,event_id,rule_id,severity,risk_score,created_at,payload,version,expires_at) VALUES (?,?,?,?,?,?,?,?,?,?)`,
		finding.TenantID, finding.ID, finding.EventID, finding.Rule.ID, finding.Severity, finding.RiskScore,
		finding.CreatedAt, string(payload), uint64(finding.CreatedAt.UnixNano()), expiresAt.UTC())
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
