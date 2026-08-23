package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/kcsp/platform/internal/core"
)

type reportRow interface{ Scan(...any) error }

func (p *Postgres) CreateReportRun(ctx context.Context, run core.ReportRun) (core.ReportRun, bool, error) {
	tx, err := p.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return core.ReportRun{}, false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if run.RequestID != "" {
		if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, run.TenantID+"|report|"+run.RequestID); err != nil {
			return core.ReportRun{}, false, err
		}
		existing, findErr := scanReportRun(tx.QueryRow(ctx, reportSelect+` WHERE tenant_id=$1 AND request_id=$2`, run.TenantID, run.RequestID))
		if findErr == nil {
			if err = tx.Commit(ctx); err != nil {
				return core.ReportRun{}, false, err
			}
			return existing, false, nil
		}
		if !errors.Is(findErr, pgx.ErrNoRows) {
			return core.ReportRun{}, false, findErr
		}
	}

	parameters, err := json.Marshal(run.Parameters)
	if err != nil {
		return core.ReportRun{}, false, fmt.Errorf("encode report parameters: %w", err)
	}
	snapshot, err := json.Marshal(run.Snapshot)
	if err != nil {
		return core.ReportRun{}, false, fmt.Errorf("encode report snapshot: %w", err)
	}
	created, err := scanReportRun(tx.QueryRow(ctx, reportInsert,
		run.TenantID, run.ID, run.Type, run.Title, run.Status, parameters, snapshot,
		run.Checksum, run.CreatedBy, run.RequestID, run.CreatedAt, run.CompletedAt,
	))
	if err != nil {
		return core.ReportRun{}, false, fmt.Errorf("create report run: %w", err)
	}
	if err = tx.Commit(ctx); err != nil {
		return core.ReportRun{}, false, err
	}
	return created, true, nil
}

func (p *Postgres) GetReportRun(ctx context.Context, tenantID, reportID string) (core.ReportRun, error) {
	run, err := scanReportRun(p.pool.QueryRow(ctx, reportSelect+` WHERE tenant_id=$1 AND report_id=$2`, tenantID, reportID))
	if errors.Is(err, pgx.ErrNoRows) {
		return core.ReportRun{}, ErrNotFound
	}
	return run, err
}

func (p *Postgres) ListReportRuns(ctx context.Context, tenantID string, filter core.ReportFilter) ([]core.ReportRun, error) {
	query := reportSelect + ` WHERE tenant_id=$1`
	args := []interface{}{tenantID}
	if reportType := strings.ToUpper(strings.TrimSpace(filter.Type)); reportType != "" {
		args = append(args, reportType)
		query += fmt.Sprintf(" AND report_type=$%d", len(args))
	}
	if status := strings.ToUpper(strings.TrimSpace(filter.Status)); status != "" {
		args = append(args, status)
		query += fmt.Sprintf(" AND status=$%d", len(args))
	}
	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	args = append(args, limit)
	query += fmt.Sprintf(" ORDER BY created_at DESC,report_id DESC LIMIT $%d", len(args))

	rows, err := p.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []core.ReportRun{}
	for rows.Next() {
		item, scanErr := scanReportRun(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

const reportColumns = `report_id,tenant_id,report_type,title,status,parameters,snapshot,checksum_sha256,created_by,request_id,created_at,completed_at`
const reportSelect = `SELECT ` + reportColumns + ` FROM report_runs`
const reportInsert = `INSERT INTO report_runs (tenant_id,report_id,report_type,title,status,parameters,snapshot,checksum_sha256,created_by,request_id,created_at,completed_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING ` + reportColumns

func scanReportRun(row reportRow) (core.ReportRun, error) {
	var run core.ReportRun
	var parameters, snapshot []byte
	if err := row.Scan(
		&run.ID, &run.TenantID, &run.Type, &run.Title, &run.Status, &parameters, &snapshot,
		&run.Checksum, &run.CreatedBy, &run.RequestID, &run.CreatedAt, &run.CompletedAt,
	); err != nil {
		return core.ReportRun{}, err
	}
	if err := json.Unmarshal(parameters, &run.Parameters); err != nil {
		return core.ReportRun{}, fmt.Errorf("decode report parameters: %w", err)
	}
	if err := json.Unmarshal(snapshot, &run.Snapshot); err != nil {
		return core.ReportRun{}, fmt.Errorf("decode report snapshot: %w", err)
	}
	return run, nil
}
