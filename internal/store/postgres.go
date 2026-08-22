package store

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/kcsp/platform/internal/core"
)

//go:embed migrations/*.sql
var migrations embed.FS

type Postgres struct {
	pool *pgxpool.Pool
}

func OpenPostgres(ctx context.Context, databaseURL string) (*Postgres, error) {
	if strings.TrimSpace(databaseURL) == "" {
		return nil, errors.New("KCSP_DATABASE_URL is required")
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse PostgreSQL configuration: %w", err)
	}
	config.MinConns = 2
	config.MaxConns = 20
	config.MaxConnLifetime = time.Hour
	config.MaxConnIdleTime = 15 * time.Minute
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("create PostgreSQL pool: %w", err)
	}
	store := &Postgres{pool: pool}
	if err := store.Health(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("connect PostgreSQL: %w", err)
	}
	if err := store.migrate(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return store, nil
}

func (p *Postgres) Health(ctx context.Context) error {
	return p.pool.Ping(ctx)
}

func (p *Postgres) Close() {
	p.pool.Close()
}

func (p *Postgres) migrate(ctx context.Context) error {
	conn, err := p.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire migration connection: %w", err)
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock(493793501)"); err != nil {
		return fmt.Errorf("lock migrations: %w", err)
	}
	defer func() { _, _ = conn.Exec(context.Background(), "SELECT pg_advisory_unlock(493793501)") }()
	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS kcsp_schema_migrations (
		version TEXT PRIMARY KEY,
		applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
	)`); err != nil {
		return fmt.Errorf("create migration ledger: %w", err)
	}
	entries, err := fs.ReadDir(migrations, "migrations")
	if err != nil {
		return fmt.Errorf("read embedded migrations: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		var applied bool
		if err := conn.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM kcsp_schema_migrations WHERE version=$1)", entry.Name()).Scan(&applied); err != nil {
			return fmt.Errorf("check migration %s: %w", entry.Name(), err)
		}
		if applied {
			continue
		}
		body, err := migrations.ReadFile("migrations/" + entry.Name())
		if err != nil {
			return fmt.Errorf("read migration %s: %w", entry.Name(), err)
		}
		tx, err := conn.Begin(ctx)
		if err != nil {
			return fmt.Errorf("begin migration %s: %w", entry.Name(), err)
		}
		if _, err := tx.Exec(ctx, string(body)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("apply migration %s: %w", entry.Name(), err)
		}
		if _, err := tx.Exec(ctx, "INSERT INTO kcsp_schema_migrations(version) VALUES($1)", entry.Name()); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("record migration %s: %w", entry.Name(), err)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit migration %s: %w", entry.Name(), err)
		}
	}
	return nil
}

func (p *Postgres) EnsureTenant(ctx context.Context, tenantID, displayName string) error {
	tenantID = strings.TrimSpace(tenantID)
	displayName = strings.TrimSpace(displayName)
	if tenantID == "" || displayName == "" {
		return errors.New("tenant id and display name are required")
	}
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tenant upsert: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `INSERT INTO tenants(tenant_id, display_name) VALUES($1,$2)
		ON CONFLICT (tenant_id) DO UPDATE SET display_name=EXCLUDED.display_name, updated_at=now()`, tenantID, displayName); err != nil {
		return fmt.Errorf("upsert tenant: %w", err)
	}
	if _, err := tx.Exec(ctx, "INSERT INTO audit_heads(tenant_id) VALUES($1) ON CONFLICT DO NOTHING", tenantID); err != nil {
		return fmt.Errorf("initialize tenant audit head: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit tenant upsert: %w", err)
	}
	return nil
}

func (p *Postgres) ResetTenant(ctx context.Context, tenantID string) error {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tenant reset: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for _, table := range []string{"ai_soc_decisions", "ai_soc_requests", "ai_soc_policies", "ueba_anomalies", "ueba_volume_windows", "ueba_entity_baselines", "audit_entries", "incidents", "alerts", "findings", "security_events", "collectors", "hunt_executions", "saved_hunts", "evidence_custody_entries", "evidence_items", "soar_connector_tests", "soar_connector_rate_windows", "soar_connectors", "soar_approval_decisions", "soar_approvals", "soar_action_attempts", "soar_node_executions", "soar_executions", "soar_playbook_versions", "soar_playbooks", "threat_intel_matches", "threat_intel_indicator_sources", "threat_intel_indicators", "threat_intel_feeds", "detection_correlation_emissions", "detection_correlation_observations", "detection_rule_versions", "tenant_retention_policies"} {
		if _, err := tx.Exec(ctx, "DELETE FROM "+table+" WHERE tenant_id=$1", tenantID); err != nil {
			return fmt.Errorf("reset tenant table %s: %w", table, err)
		}
	}
	if _, err := tx.Exec(ctx, "UPDATE audit_heads SET head_hash='' WHERE tenant_id=$1", tenantID); err != nil {
		return fmt.Errorf("reset audit head: %w", err)
	}
	return tx.Commit(ctx)
}

func (p *Postgres) SetRules(ctx context.Context, rules []core.DetectionRule) error {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin rule upsert: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for _, rule := range rules {
		payload, err := json.Marshal(rule)
		if err != nil {
			return fmt.Errorf("encode rule %s: %w", rule.ID, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO detection_rules(rule_id,updated_at,payload) VALUES($1,$2,$3)
			ON CONFLICT(rule_id) DO UPDATE SET updated_at=EXCLUDED.updated_at,payload=EXCLUDED.payload`, rule.ID, rule.UpdatedAt, payload); err != nil {
			return fmt.Errorf("upsert rule %s: %w", rule.ID, err)
		}
	}
	return tx.Commit(ctx)
}

func (p *Postgres) ListRules(ctx context.Context) ([]core.DetectionRule, error) {
	rows, err := p.pool.Query(ctx, "SELECT payload FROM detection_rules ORDER BY updated_at DESC")
	if err != nil {
		return nil, fmt.Errorf("list rules: %w", err)
	}
	defer rows.Close()
	result := []core.DetectionRule{}
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return nil, fmt.Errorf("scan rule: %w", err)
		}
		var rule core.DetectionRule
		if err := json.Unmarshal(payload, &rule); err != nil {
			return nil, fmt.Errorf("decode rule: %w", err)
		}
		result = append(result, rule)
	}
	return result, rows.Err()
}

func (p *Postgres) PutEvent(ctx context.Context, event core.CanonicalEvent) (core.CanonicalEvent, bool, error) {
	payload, err := json.Marshal(event)
	if err != nil {
		return core.CanonicalEvent{}, false, fmt.Errorf("encode event: %w", err)
	}
	tag, err := p.pool.Exec(ctx, `INSERT INTO security_events
		(tenant_id,event_id,event_time,ingest_time,category,severity,raw_hash,payload)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING`,
		event.TenantID, event.ID, event.EventTime, event.IngestTime, event.Category, event.Severity, event.Raw.Hash, payload)
	if err != nil {
		return core.CanonicalEvent{}, false, fmt.Errorf("store event: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return event, false, nil
	}
	existing, err := p.GetEvent(ctx, event.TenantID, event.ID)
	return existing, true, err
}

func (p *Postgres) GetEvent(ctx context.Context, tenantID, eventID string) (core.CanonicalEvent, error) {
	var payload []byte
	err := p.pool.QueryRow(ctx, "SELECT payload FROM security_events WHERE tenant_id=$1 AND event_id=$2", tenantID, eventID).Scan(&payload)
	if errors.Is(err, pgx.ErrNoRows) {
		return core.CanonicalEvent{}, ErrNotFound
	}
	if err != nil {
		return core.CanonicalEvent{}, fmt.Errorf("get event: %w", err)
	}
	var event core.CanonicalEvent
	if err := json.Unmarshal(payload, &event); err != nil {
		return core.CanonicalEvent{}, fmt.Errorf("decode event: %w", err)
	}
	return event, nil
}

func (p *Postgres) ListEvents(ctx context.Context, tenantID string, filter EventFilter) ([]core.CanonicalEvent, error) {
	args := []interface{}{tenantID}
	where := []string{"tenant_id=$1"}
	if filter.Category != "" {
		args = append(args, filter.Category)
		where = append(where, fmt.Sprintf("lower(category)=lower($%d)", len(args)))
	}
	if filter.Severity > 0 {
		args = append(args, filter.Severity)
		where = append(where, fmt.Sprintf("severity=$%d", len(args)))
	}
	if query := strings.TrimSpace(filter.Query); query != "" {
		args = append(args, "%"+query+"%")
		where = append(where, fmt.Sprintf("payload::text ILIKE $%d", len(args)))
	}
	args = append(args, normalizedLimit(filter.Limit))
	query := "SELECT payload FROM security_events WHERE " + strings.Join(where, " AND ") + fmt.Sprintf(" ORDER BY event_time DESC LIMIT $%d", len(args))
	rows, err := p.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list events: %w", err)
	}
	defer rows.Close()
	result := []core.CanonicalEvent{}
	for rows.Next() {
		var payload []byte
		var event core.CanonicalEvent
		if err := rows.Scan(&payload); err != nil {
			return nil, fmt.Errorf("scan event: %w", err)
		}
		if err := json.Unmarshal(payload, &event); err != nil {
			return nil, fmt.Errorf("decode event: %w", err)
		}
		result = append(result, event)
	}
	return result, rows.Err()
}

func (p *Postgres) PutFinding(ctx context.Context, finding core.Finding) error {
	payload, err := json.Marshal(finding)
	if err != nil {
		return fmt.Errorf("encode finding: %w", err)
	}
	_, err = p.pool.Exec(ctx, `INSERT INTO findings(tenant_id,finding_id,event_id,created_at,payload)
		VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING`, finding.TenantID, finding.ID, finding.EventID, finding.CreatedAt, payload)
	if err != nil {
		return fmt.Errorf("store finding: %w", err)
	}
	return nil
}

func (p *Postgres) ListFindings(ctx context.Context, tenantID, eventID string, limit int) ([]core.Finding, error) {
	args := []interface{}{tenantID}
	where := "tenant_id=$1"
	if eventID != "" {
		args = append(args, eventID)
		where += fmt.Sprintf(" AND event_id=$%d", len(args))
	}
	args = append(args, normalizedLimit(limit))
	rows, err := p.pool.Query(ctx, "SELECT payload FROM findings WHERE "+where+fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d", len(args)), args...)
	if err != nil {
		return nil, fmt.Errorf("list findings: %w", err)
	}
	defer rows.Close()
	result := []core.Finding{}
	for rows.Next() {
		var payload []byte
		var finding core.Finding
		if err := rows.Scan(&payload); err != nil {
			return nil, fmt.Errorf("scan finding: %w", err)
		}
		if err := json.Unmarshal(payload, &finding); err != nil {
			return nil, fmt.Errorf("decode finding: %w", err)
		}
		result = append(result, finding)
	}
	return result, rows.Err()
}

func (p *Postgres) UpsertAlert(ctx context.Context, candidate core.Alert, dedupKey string, window time.Duration) (core.Alert, bool, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return core.Alert{}, false, fmt.Errorf("begin alert upsert: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	lockKey := candidate.TenantID + "|" + dedupKey
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", lockKey); err != nil {
		return core.Alert{}, false, fmt.Errorf("lock alert deduplication key: %w", err)
	}
	var payload []byte
	err = tx.QueryRow(ctx, `SELECT payload FROM alerts
		WHERE tenant_id=$1 AND dedup_key=$2 AND status<>'CLOSED'
		ORDER BY last_seen DESC LIMIT 1 FOR UPDATE`, candidate.TenantID, dedupKey).Scan(&payload)
	if err == nil {
		var existing core.Alert
		if err := json.Unmarshal(payload, &existing); err != nil {
			return core.Alert{}, false, fmt.Errorf("decode deduplicated alert: %w", err)
		}
		if candidate.LastSeen.Sub(existing.LastSeen) <= window {
			existing.FindingIDs = appendUnique(existing.FindingIDs, candidate.FindingIDs...)
			existing.EventIDs = appendUnique(existing.EventIDs, candidate.EventIDs...)
			existing.EventCount = len(existing.EventIDs)
			existing.LastSeen = candidate.LastSeen
			existing.UpdatedAt = candidate.UpdatedAt
			existing.Version++
			if candidate.RiskScore > existing.RiskScore {
				existing.RiskScore = candidate.RiskScore
				existing.RiskBreakdown = candidate.RiskBreakdown
				existing.Severity = candidate.Severity
			}
			if err := updateAlertRow(ctx, tx, existing, dedupKey); err != nil {
				return core.Alert{}, false, err
			}
			if err := tx.Commit(ctx); err != nil {
				return core.Alert{}, false, fmt.Errorf("commit alert aggregation: %w", err)
			}
			return existing, false, nil
		}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return core.Alert{}, false, fmt.Errorf("find deduplicated alert: %w", err)
	}
	payload, err = json.Marshal(candidate)
	if err != nil {
		return core.Alert{}, false, fmt.Errorf("encode alert: %w", err)
	}
	_, err = tx.Exec(ctx, `INSERT INTO alerts
		(tenant_id,alert_id,dedup_key,status,severity,assignee,risk_score,first_seen,last_seen,version,created_at,updated_at,payload)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, candidate.TenantID, candidate.ID, dedupKey,
		candidate.Status, candidate.Severity, candidate.Assignee, candidate.RiskScore, candidate.FirstSeen, candidate.LastSeen,
		candidate.Version, candidate.CreatedAt, candidate.UpdatedAt, payload)
	if err != nil {
		return core.Alert{}, false, fmt.Errorf("insert alert: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return core.Alert{}, false, fmt.Errorf("commit alert insert: %w", err)
	}
	return candidate, true, nil
}

func (p *Postgres) GetAlert(ctx context.Context, tenantID, alertID string) (core.Alert, error) {
	var payload []byte
	err := p.pool.QueryRow(ctx, "SELECT payload FROM alerts WHERE tenant_id=$1 AND alert_id=$2", tenantID, alertID).Scan(&payload)
	if errors.Is(err, pgx.ErrNoRows) {
		return core.Alert{}, ErrNotFound
	}
	if err != nil {
		return core.Alert{}, fmt.Errorf("get alert: %w", err)
	}
	var alert core.Alert
	if err := json.Unmarshal(payload, &alert); err != nil {
		return core.Alert{}, fmt.Errorf("decode alert: %w", err)
	}
	return alert, nil
}

func (p *Postgres) ListAlerts(ctx context.Context, tenantID string, filter AlertFilter) ([]core.Alert, error) {
	args := []interface{}{tenantID}
	where := []string{"tenant_id=$1"}
	if filter.Status != "" {
		args = append(args, strings.ToUpper(filter.Status))
		where = append(where, fmt.Sprintf("status=$%d", len(args)))
	}
	if filter.Severity != "" {
		args = append(args, filter.Severity)
		where = append(where, fmt.Sprintf("severity=$%d", len(args)))
	}
	if filter.Assignee != "" {
		args = append(args, filter.Assignee)
		where = append(where, fmt.Sprintf("lower(assignee)=lower($%d)", len(args)))
	}
	if query := strings.TrimSpace(filter.Query); query != "" {
		args = append(args, "%"+query+"%")
		where = append(where, fmt.Sprintf("payload::text ILIKE $%d", len(args)))
	}
	args = append(args, normalizedLimit(filter.Limit))
	rows, err := p.pool.Query(ctx, "SELECT payload FROM alerts WHERE "+strings.Join(where, " AND ")+fmt.Sprintf(" ORDER BY updated_at DESC LIMIT $%d", len(args)), args...)
	if err != nil {
		return nil, fmt.Errorf("list alerts: %w", err)
	}
	defer rows.Close()
	return scanAlerts(rows)
}

func (p *Postgres) MutateAlert(ctx context.Context, tenantID, alertID string, expectedVersion int, mutate func(*core.Alert) error) (core.Alert, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return core.Alert{}, fmt.Errorf("begin alert mutation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var payload []byte
	var dedupKey string
	err = tx.QueryRow(ctx, "SELECT payload,dedup_key FROM alerts WHERE tenant_id=$1 AND alert_id=$2 FOR UPDATE", tenantID, alertID).Scan(&payload, &dedupKey)
	if errors.Is(err, pgx.ErrNoRows) {
		return core.Alert{}, ErrNotFound
	}
	if err != nil {
		return core.Alert{}, fmt.Errorf("lock alert: %w", err)
	}
	var alert core.Alert
	if err := json.Unmarshal(payload, &alert); err != nil {
		return core.Alert{}, fmt.Errorf("decode alert: %w", err)
	}
	if expectedVersion > 0 && alert.Version != expectedVersion {
		return core.Alert{}, ErrVersionConflict
	}
	if err := mutate(&alert); err != nil {
		return core.Alert{}, err
	}
	alert.Version++
	alert.UpdatedAt = time.Now().UTC()
	if err := updateAlertRow(ctx, tx, alert, dedupKey); err != nil {
		return core.Alert{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return core.Alert{}, fmt.Errorf("commit alert mutation: %w", err)
	}
	return alert, nil
}

func updateAlertRow(ctx context.Context, tx pgx.Tx, alert core.Alert, dedupKey string) error {
	payload, err := json.Marshal(alert)
	if err != nil {
		return fmt.Errorf("encode alert: %w", err)
	}
	_, err = tx.Exec(ctx, `UPDATE alerts SET dedup_key=$3,status=$4,severity=$5,assignee=$6,risk_score=$7,
		first_seen=$8,last_seen=$9,version=$10,created_at=$11,updated_at=$12,payload=$13
		WHERE tenant_id=$1 AND alert_id=$2`, alert.TenantID, alert.ID, dedupKey, alert.Status, alert.Severity, alert.Assignee,
		alert.RiskScore, alert.FirstSeen, alert.LastSeen, alert.Version, alert.CreatedAt, alert.UpdatedAt, payload)
	if err != nil {
		return fmt.Errorf("update alert: %w", err)
	}
	return nil
}

func scanAlerts(rows pgx.Rows) ([]core.Alert, error) {
	result := []core.Alert{}
	for rows.Next() {
		var payload []byte
		var alert core.Alert
		if err := rows.Scan(&payload); err != nil {
			return nil, fmt.Errorf("scan alert: %w", err)
		}
		if err := json.Unmarshal(payload, &alert); err != nil {
			return nil, fmt.Errorf("decode alert: %w", err)
		}
		result = append(result, alert)
	}
	return result, rows.Err()
}

func (p *Postgres) CreateIncident(ctx context.Context, incident core.Incident) (core.Incident, error) {
	payload, err := json.Marshal(incident)
	if err != nil {
		return core.Incident{}, fmt.Errorf("encode incident: %w", err)
	}
	_, err = p.pool.Exec(ctx, `INSERT INTO incidents
		(tenant_id,incident_id,status,severity,assignee,risk_score,version,created_at,updated_at,payload)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, incident.TenantID, incident.ID, incident.Status, incident.Severity,
		incident.Assignee, incident.RiskScore, incident.Version, incident.CreatedAt, incident.UpdatedAt, payload)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			return core.Incident{}, ErrVersionConflict
		}
		return core.Incident{}, fmt.Errorf("create incident: %w", err)
	}
	return incident, nil
}

func (p *Postgres) GetIncident(ctx context.Context, tenantID, incidentID string) (core.Incident, error) {
	var payload []byte
	err := p.pool.QueryRow(ctx, "SELECT payload FROM incidents WHERE tenant_id=$1 AND incident_id=$2", tenantID, incidentID).Scan(&payload)
	if errors.Is(err, pgx.ErrNoRows) {
		return core.Incident{}, ErrNotFound
	}
	if err != nil {
		return core.Incident{}, fmt.Errorf("get incident: %w", err)
	}
	var incident core.Incident
	if err := json.Unmarshal(payload, &incident); err != nil {
		return core.Incident{}, fmt.Errorf("decode incident: %w", err)
	}
	return incident, nil
}

func (p *Postgres) ListIncidents(ctx context.Context, tenantID string, filter IncidentFilter) ([]core.Incident, error) {
	args := []interface{}{tenantID}
	where := []string{"tenant_id=$1"}
	if filter.Status != "" {
		args = append(args, strings.ToUpper(filter.Status))
		where = append(where, fmt.Sprintf("status=$%d", len(args)))
	}
	if filter.Severity != "" {
		args = append(args, filter.Severity)
		where = append(where, fmt.Sprintf("severity=$%d", len(args)))
	}
	if query := strings.TrimSpace(filter.Query); query != "" {
		args = append(args, "%"+query+"%")
		where = append(where, fmt.Sprintf("payload::text ILIKE $%d", len(args)))
	}
	args = append(args, normalizedLimit(filter.Limit))
	rows, err := p.pool.Query(ctx, "SELECT payload FROM incidents WHERE "+strings.Join(where, " AND ")+fmt.Sprintf(" ORDER BY updated_at DESC LIMIT $%d", len(args)), args...)
	if err != nil {
		return nil, fmt.Errorf("list incidents: %w", err)
	}
	defer rows.Close()
	result := []core.Incident{}
	for rows.Next() {
		var payload []byte
		var incident core.Incident
		if err := rows.Scan(&payload); err != nil {
			return nil, fmt.Errorf("scan incident: %w", err)
		}
		if err := json.Unmarshal(payload, &incident); err != nil {
			return nil, fmt.Errorf("decode incident: %w", err)
		}
		result = append(result, incident)
	}
	return result, rows.Err()
}

func (p *Postgres) MutateIncident(ctx context.Context, tenantID, incidentID string, expectedVersion int, mutate func(*core.Incident) error) (core.Incident, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return core.Incident{}, fmt.Errorf("begin incident mutation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var payload []byte
	err = tx.QueryRow(ctx, "SELECT payload FROM incidents WHERE tenant_id=$1 AND incident_id=$2 FOR UPDATE", tenantID, incidentID).Scan(&payload)
	if errors.Is(err, pgx.ErrNoRows) {
		return core.Incident{}, ErrNotFound
	}
	if err != nil {
		return core.Incident{}, fmt.Errorf("lock incident: %w", err)
	}
	var incident core.Incident
	if err := json.Unmarshal(payload, &incident); err != nil {
		return core.Incident{}, fmt.Errorf("decode incident: %w", err)
	}
	if expectedVersion > 0 && incident.Version != expectedVersion {
		return core.Incident{}, ErrVersionConflict
	}
	if err := mutate(&incident); err != nil {
		return core.Incident{}, err
	}
	incident.Version++
	incident.UpdatedAt = time.Now().UTC()
	payload, err = json.Marshal(incident)
	if err != nil {
		return core.Incident{}, fmt.Errorf("encode incident: %w", err)
	}
	_, err = tx.Exec(ctx, `UPDATE incidents SET status=$3,severity=$4,assignee=$5,risk_score=$6,version=$7,
		created_at=$8,updated_at=$9,payload=$10 WHERE tenant_id=$1 AND incident_id=$2`, tenantID, incidentID,
		incident.Status, incident.Severity, incident.Assignee, incident.RiskScore, incident.Version, incident.CreatedAt, incident.UpdatedAt, payload)
	if err != nil {
		return core.Incident{}, fmt.Errorf("update incident: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return core.Incident{}, fmt.Errorf("commit incident mutation: %w", err)
	}
	return incident, nil
}

func (p *Postgres) AppendAudit(ctx context.Context, entry core.AuditEntry) (core.AuditEntry, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return core.AuditEntry{}, fmt.Errorf("begin audit append: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, "INSERT INTO audit_heads(tenant_id) VALUES($1) ON CONFLICT DO NOTHING", entry.TenantID); err != nil {
		return core.AuditEntry{}, fmt.Errorf("ensure audit head: %w", err)
	}
	if err := tx.QueryRow(ctx, "SELECT head_hash FROM audit_heads WHERE tenant_id=$1 FOR UPDATE", entry.TenantID).Scan(&entry.PreviousHash); err != nil {
		return core.AuditEntry{}, fmt.Errorf("lock audit head: %w", err)
	}
	if entry.ID == "" {
		entry.ID = core.NewID("aud")
	}
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = time.Now().UTC()
	}
	entry.Hash = auditHash(entry)
	payload, err := json.Marshal(entry)
	if err != nil {
		return core.AuditEntry{}, fmt.Errorf("encode audit entry: %w", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO audit_entries
		(tenant_id,audit_id,previous_hash,entry_hash,created_at,payload) VALUES($1,$2,$3,$4,$5,$6)`,
		entry.TenantID, entry.ID, entry.PreviousHash, entry.Hash, entry.CreatedAt, payload); err != nil {
		return core.AuditEntry{}, fmt.Errorf("append audit entry: %w", err)
	}
	if _, err := tx.Exec(ctx, "UPDATE audit_heads SET head_hash=$2 WHERE tenant_id=$1", entry.TenantID, entry.Hash); err != nil {
		return core.AuditEntry{}, fmt.Errorf("advance audit head: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return core.AuditEntry{}, fmt.Errorf("commit audit append: %w", err)
	}
	return entry, nil
}

func (p *Postgres) ListAudit(ctx context.Context, tenantID string, limit int) ([]core.AuditEntry, error) {
	rows, err := p.pool.Query(ctx, "SELECT payload FROM audit_entries WHERE tenant_id=$1 ORDER BY sequence_id DESC LIMIT $2", tenantID, normalizedLimit(limit))
	if err != nil {
		return nil, fmt.Errorf("list audit entries: %w", err)
	}
	defer rows.Close()
	result := []core.AuditEntry{}
	for rows.Next() {
		var payload []byte
		var entry core.AuditEntry
		if err := rows.Scan(&payload); err != nil {
			return nil, fmt.Errorf("scan audit entry: %w", err)
		}
		if err := json.Unmarshal(payload, &entry); err != nil {
			return nil, fmt.Errorf("decode audit entry: %w", err)
		}
		result = append(result, entry)
	}
	return result, rows.Err()
}

func (p *Postgres) VerifyAudit(ctx context.Context, tenantID string) (bool, error) {
	rows, err := p.pool.Query(ctx, "SELECT payload FROM audit_entries WHERE tenant_id=$1 ORDER BY sequence_id", tenantID)
	if err != nil {
		return false, fmt.Errorf("read audit chain: %w", err)
	}
	defer rows.Close()
	previous := ""
	for rows.Next() {
		var payload []byte
		var entry core.AuditEntry
		if err := rows.Scan(&payload); err != nil {
			return false, fmt.Errorf("scan audit chain: %w", err)
		}
		if err := json.Unmarshal(payload, &entry); err != nil {
			return false, fmt.Errorf("decode audit chain: %w", err)
		}
		if entry.PreviousHash != previous || auditHash(entry) != entry.Hash {
			return false, nil
		}
		previous = entry.Hash
	}
	if err := rows.Err(); err != nil {
		return false, err
	}
	var head string
	err = p.pool.QueryRow(ctx, "SELECT head_hash FROM audit_heads WHERE tenant_id=$1", tenantID).Scan(&head)
	if errors.Is(err, pgx.ErrNoRows) {
		return previous == "", nil
	}
	if err != nil {
		return false, fmt.Errorf("read audit head: %w", err)
	}
	return previous == head, nil
}

func (p *Postgres) Overview(ctx context.Context, tenantID string) (map[string]interface{}, error) {
	var tenantName string
	if err := p.pool.QueryRow(ctx, "SELECT display_name FROM tenants WHERE tenant_id=$1", tenantID).Scan(&tenantName); errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, fmt.Errorf("read tenant overview: %w", err)
	}
	var events24h, openAlerts, criticalAlerts, unassignedAlerts, activeIncidents int
	var latencyMS float64
	if err := p.pool.QueryRow(ctx, "SELECT count(*) FROM security_events WHERE tenant_id=$1 AND ingest_time >= now()-interval '24 hours'", tenantID).Scan(&events24h); err != nil {
		return nil, fmt.Errorf("count events: %w", err)
	}
	if err := p.pool.QueryRow(ctx, `SELECT count(*),count(*) FILTER (WHERE severity='CRITICAL'),count(*) FILTER (WHERE assignee='')
		FROM alerts WHERE tenant_id=$1 AND status<>'CLOSED'`, tenantID).Scan(&openAlerts, &criticalAlerts, &unassignedAlerts); err != nil {
		return nil, fmt.Errorf("count alerts: %w", err)
	}
	if err := p.pool.QueryRow(ctx, "SELECT count(*) FROM incidents WHERE tenant_id=$1 AND status<>'CLOSED'", tenantID).Scan(&activeIncidents); err != nil {
		return nil, fmt.Errorf("count incidents: %w", err)
	}
	if err := p.pool.QueryRow(ctx, `SELECT COALESCE(avg(EXTRACT(EPOCH FROM (f.created_at-e.ingest_time))*1000),0)
		FROM findings f JOIN security_events e USING(tenant_id,event_id) WHERE f.tenant_id=$1`, tenantID).Scan(&latencyMS); err != nil {
		return nil, fmt.Errorf("measure detection latency: %w", err)
	}
	severityCounts := map[core.Severity]int{}
	rows, err := p.pool.Query(ctx, "SELECT severity,count(*) FROM alerts WHERE tenant_id=$1 AND status<>'CLOSED' GROUP BY severity", tenantID)
	if err != nil {
		return nil, fmt.Errorf("group alert severities: %w", err)
	}
	for rows.Next() {
		var severity core.Severity
		var count int
		if err := rows.Scan(&severity, &count); err != nil {
			rows.Close()
			return nil, err
		}
		severityCounts[severity] = count
	}
	rows.Close()
	topRules := []map[string]interface{}{}
	rows, err = p.pool.Query(ctx, `SELECT COALESCE(payload->'rule'->>'title','Unknown'),count(*)
		FROM alerts WHERE tenant_id=$1 AND status<>'CLOSED' GROUP BY 1 ORDER BY 2 DESC LIMIT 10`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list top rules: %w", err)
	}
	for rows.Next() {
		var title string
		var count int
		if err := rows.Scan(&title, &count); err != nil {
			rows.Close()
			return nil, err
		}
		topRules = append(topRules, map[string]interface{}{"title": title, "count": count})
	}
	rows.Close()
	var recentEvents int
	if err := p.pool.QueryRow(ctx, "SELECT count(*) FROM security_events WHERE tenant_id=$1 AND ingest_time >= now()-interval '5 minutes'", tenantID).Scan(&recentEvents); err != nil {
		return nil, fmt.Errorf("measure ingest rate: %w", err)
	}
	now := time.Now().UTC()
	return map[string]interface{}{
		"tenant": map[string]string{"id": tenantID, "name": tenantName},
		"metrics": map[string]interface{}{
			"events_24h": events24h, "open_alerts": openAlerts, "critical_alerts": criticalAlerts,
			"unassigned_alerts": unassignedAlerts, "active_incidents": activeIncidents, "detection_latency_ms": int(latencyMS),
		},
		"severity_distribution": []map[string]interface{}{
			{"severity": core.SeverityCritical, "count": severityCounts[core.SeverityCritical]},
			{"severity": core.SeverityHigh, "count": severityCounts[core.SeverityHigh]},
			{"severity": core.SeverityMedium, "count": severityCounts[core.SeverityMedium]},
			{"severity": core.SeverityLow, "count": severityCounts[core.SeverityLow]},
		},
		"top_rules": topRules,
		"platform": map[string]interface{}{
			"status": "OPERATIONAL", "profile": "durable-postgres", "ingest_eps": float64(recentEvents) / 300,
			"sources_healthy": 0, "sources_total": 0, "parser_errors_24h": 0,
		},
		"generated_at": now,
	}, nil
}
