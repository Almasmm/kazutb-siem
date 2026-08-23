package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kcsp/platform/internal/core"
)

type CaseStore interface {
	CreateCase(context.Context, core.Case) (core.Case, bool, error)
	GetCase(context.Context, string, string) (core.Case, error)
	ListCases(context.Context, string, core.CaseFilter) ([]core.Case, error)
	MutateCase(context.Context, string, string, int, func(*core.Case) error) (core.Case, error)
}

func (p *Postgres) CreateCase(ctx context.Context, item core.Case) (core.Case, bool, error) {
	if item.ID == "" || item.TenantID == "" || item.RequestID == "" || item.Title == "" || item.Owner == "" || item.Version < 1 {
		return core.Case{}, false, errors.New("create case: required fields are missing")
	}
	payload, err := json.Marshal(item)
	if err != nil {
		return core.Case{}, false, err
	}
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return core.Case{}, false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	created, err := scanCase(tx.QueryRow(ctx, `INSERT INTO cases(tenant_id,case_id,request_id,status,severity,owner,version,created_at,updated_at,payload)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT (tenant_id,request_id) DO NOTHING RETURNING `+caseColumns,
		item.TenantID, item.ID, item.RequestID, item.Status, item.Severity, item.Owner, item.Version, item.CreatedAt, item.UpdatedAt, payload))
	if errors.Is(err, pgx.ErrNoRows) {
		_ = tx.Rollback(ctx)
		existing, lookupErr := p.caseByRequestID(ctx, item.TenantID, item.RequestID)
		return existing, true, lookupErr
	}
	if err != nil {
		return core.Case{}, false, fmt.Errorf("insert case: %w", err)
	}
	if err := syncCaseIncidents(ctx, tx, created); err != nil {
		return core.Case{}, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return core.Case{}, false, err
	}
	return created, false, nil
}

func (p *Postgres) GetCase(ctx context.Context, tenantID, caseID string) (core.Case, error) {
	item, err := scanCase(p.pool.QueryRow(ctx, `SELECT `+caseColumns+` FROM cases WHERE tenant_id=$1 AND case_id=$2`, tenantID, caseID))
	if errors.Is(err, pgx.ErrNoRows) {
		return core.Case{}, ErrNotFound
	}
	if err != nil {
		return core.Case{}, fmt.Errorf("get case: %w", err)
	}
	return item, nil
}

func (p *Postgres) caseByRequestID(ctx context.Context, tenantID, requestID string) (core.Case, error) {
	item, err := scanCase(p.pool.QueryRow(ctx, `SELECT `+caseColumns+` FROM cases WHERE tenant_id=$1 AND request_id=$2`, tenantID, requestID))
	if errors.Is(err, pgx.ErrNoRows) {
		return core.Case{}, ErrNotFound
	}
	return item, err
}

func (p *Postgres) ListCases(ctx context.Context, tenantID string, filter core.CaseFilter) ([]core.Case, error) {
	args := []interface{}{tenantID}
	where := []string{"c.tenant_id=$1"}
	add := func(expression string, value interface{}) {
		args = append(args, value)
		where = append(where, fmt.Sprintf(expression, len(args)))
	}
	if filter.Status != "" {
		add("c.status=$%d", strings.ToUpper(filter.Status))
	}
	if filter.Severity != "" {
		add("c.severity=$%d", strings.ToUpper(filter.Severity))
	}
	if filter.Owner != "" {
		add("c.owner=$%d", filter.Owner)
	}
	if filter.IncidentID != "" {
		add("EXISTS (SELECT 1 FROM case_incidents ci WHERE ci.tenant_id=c.tenant_id AND ci.case_id=c.case_id AND ci.incident_id=$%d)", filter.IncidentID)
	}
	if filter.Query != "" {
		args = append(args, filter.Query)
		position := len(args)
		where = append(where, fmt.Sprintf("(c.case_id ILIKE '%%'||$%d||'%%' OR c.payload->>'title' ILIKE '%%'||$%d||'%%' OR c.payload->>'description' ILIKE '%%'||$%d||'%%')", position, position, position))
	}
	args = append(args, normalizedLimit(filter.Limit))
	rows, err := p.pool.Query(ctx, `SELECT `+caseColumns+` FROM cases c WHERE `+strings.Join(where, " AND ")+` ORDER BY c.updated_at DESC LIMIT $`+fmt.Sprint(len(args)), args...)
	if err != nil {
		return nil, fmt.Errorf("list cases: %w", err)
	}
	defer rows.Close()
	items := []core.Case{}
	for rows.Next() {
		item, err := scanCase(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (p *Postgres) MutateCase(ctx context.Context, tenantID, caseID string, expectedVersion int, mutate func(*core.Case) error) (core.Case, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return core.Case{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var payload []byte
	var version int
	if err := tx.QueryRow(ctx, `SELECT payload,version FROM cases WHERE tenant_id=$1 AND case_id=$2 FOR UPDATE`, tenantID, caseID).Scan(&payload, &version); errors.Is(err, pgx.ErrNoRows) {
		return core.Case{}, ErrNotFound
	} else if err != nil {
		return core.Case{}, err
	}
	if expectedVersion > 0 && expectedVersion != version {
		return core.Case{}, ErrVersionConflict
	}
	var item core.Case
	if err := json.Unmarshal(payload, &item); err != nil {
		return core.Case{}, err
	}
	if err := mutate(&item); err != nil {
		return core.Case{}, err
	}
	if item.ID != caseID || item.TenantID != tenantID {
		return core.Case{}, errors.New("case mutation changed immutable identity")
	}
	item.Version = version + 1
	item.UpdatedAt = time.Now().UTC()
	payload, err = json.Marshal(item)
	if err != nil {
		return core.Case{}, err
	}
	updated, err := scanCase(tx.QueryRow(ctx, `UPDATE cases SET status=$3,severity=$4,owner=$5,version=$6,updated_at=$7,payload=$8 WHERE tenant_id=$1 AND case_id=$2 RETURNING `+caseColumns,
		tenantID, caseID, item.Status, item.Severity, item.Owner, item.Version, item.UpdatedAt, payload))
	if err != nil {
		return core.Case{}, err
	}
	if err := syncCaseIncidents(ctx, tx, updated); err != nil {
		return core.Case{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return core.Case{}, err
	}
	return updated, nil
}

func syncCaseIncidents(ctx context.Context, tx pgx.Tx, item core.Case) error {
	if _, err := tx.Exec(ctx, `DELETE FROM case_incidents WHERE tenant_id=$1 AND case_id=$2`, item.TenantID, item.ID); err != nil {
		return err
	}
	for _, incidentID := range item.IncidentIDs {
		if _, err := tx.Exec(ctx, `INSERT INTO case_incidents(tenant_id,case_id,incident_id,linked_at) VALUES($1,$2,$3,$4)`, item.TenantID, item.ID, incidentID, item.UpdatedAt); err != nil {
			return fmt.Errorf("link case incident %s: %w", incidentID, err)
		}
	}
	return nil
}

const caseColumns = `tenant_id,case_id,request_id,status,severity,owner,version,created_at,updated_at,payload`

func scanCase(scanner detectionScanner) (core.Case, error) {
	var item core.Case
	var payload []byte
	var severity string
	if err := scanner.Scan(&item.TenantID, &item.ID, &item.RequestID, &item.Status, &severity, &item.Owner, &item.Version, &item.CreatedAt, &item.UpdatedAt, &payload); err != nil {
		return core.Case{}, err
	}
	if err := json.Unmarshal(payload, &item); err != nil {
		return core.Case{}, err
	}
	item.Severity = core.Severity(severity)
	return item, nil
}
