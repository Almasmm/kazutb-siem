package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/kcsp/platform/internal/core"
)

func (p *Postgres) CreateDetectionDraft(ctx context.Context, content core.DetectionContent) (core.DetectionContent, error) {
	positive, _ := json.Marshal(content.PositiveTests)
	negative, _ := json.Marshal(content.NegativeTests)
	rule, _ := json.Marshal(content.Rule)
	validation, _ := json.Marshal(content.Validation)
	now := time.Now().UTC()
	created, err := scanDetectionContent(p.pool.QueryRow(ctx, `INSERT INTO detection_rule_versions
		(tenant_id,rule_id,version,state,sigma_yaml,positive_tests,negative_tests,rule_metadata,validation_report,
		 performance_budget_micros,created_by,created_at,updated_at)
		VALUES($1,$2,$3,'DRAFT',$4,$5,$6,$7,$8,$9,$10,$11,$11)
		RETURNING tenant_id,rule_id,version,state,sigma_yaml,positive_tests,negative_tests,rule_metadata,validation_report,
		 performance_budget_micros,created_by,created_at,updated_at,published_at`, content.TenantID, content.RuleID, content.Version,
		content.SigmaYAML, positive, negative, rule, validation, content.PerformanceBudgetMicros, content.CreatedBy, now))
	if err != nil {
		var postgresError *pgconn.PgError
		if errors.As(err, &postgresError) && postgresError.Code == "23505" {
			return core.DetectionContent{}, fmt.Errorf("%w: detection version already exists", ErrAlreadyExists)
		}
		return core.DetectionContent{}, fmt.Errorf("create detection draft: %w", err)
	}
	return created, nil
}

func (p *Postgres) DetectionContent(ctx context.Context, tenantID, ruleID, version string) (core.DetectionContent, error) {
	content, err := scanDetectionContent(p.pool.QueryRow(ctx, detectionContentSelect+` WHERE tenant_id=$1 AND rule_id=$2 AND version=$3`, tenantID, ruleID, version))
	if errors.Is(err, pgx.ErrNoRows) {
		return core.DetectionContent{}, ErrNotFound
	}
	if err != nil {
		return core.DetectionContent{}, fmt.Errorf("get detection content: %w", err)
	}
	return content, nil
}

func (p *Postgres) ListDetectionContent(ctx context.Context, tenantID string) ([]core.DetectionContent, error) {
	rows, err := p.pool.Query(ctx, detectionContentSelect+` WHERE tenant_id=$1 ORDER BY rule_id,created_at DESC`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list detection content: %w", err)
	}
	defer rows.Close()
	return collectDetectionRows(rows)
}

func (p *Postgres) PublishedDetectionContent(ctx context.Context, tenantID string) ([]core.DetectionContent, error) {
	rows, err := p.pool.Query(ctx, detectionContentSelect+` WHERE tenant_id=$1 AND state='PUBLISHED' ORDER BY rule_id`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list published detection content: %w", err)
	}
	defer rows.Close()
	return collectDetectionRows(rows)
}

func (p *Postgres) SaveDetectionValidation(ctx context.Context, content core.DetectionContent, rule core.DetectionRule, report core.DetectionValidationReport) (core.DetectionContent, error) {
	rulePayload, _ := json.Marshal(rule)
	reportPayload, _ := json.Marshal(report)
	state := "DRAFT"
	if report.Valid {
		state = "VALIDATED"
	}
	updated, err := scanDetectionContent(p.pool.QueryRow(ctx, `UPDATE detection_rule_versions SET state=$4,rule_metadata=$5,
		validation_report=$6,updated_at=$7 WHERE tenant_id=$1 AND rule_id=$2 AND version=$3 AND state IN ('DRAFT','VALIDATED')
		RETURNING tenant_id,rule_id,version,state,sigma_yaml,positive_tests,negative_tests,rule_metadata,validation_report,
		 performance_budget_micros,created_by,created_at,updated_at,published_at`, content.TenantID, content.RuleID, content.Version,
		state, rulePayload, reportPayload, time.Now().UTC()))
	if errors.Is(err, pgx.ErrNoRows) {
		return core.DetectionContent{}, ErrVersionConflict
	}
	if err != nil {
		return core.DetectionContent{}, fmt.Errorf("save detection validation: %w", err)
	}
	return updated, nil
}

func (p *Postgres) PublishDetectionContent(ctx context.Context, tenantID, ruleID, version string) (core.DetectionContent, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return core.DetectionContent{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1),hashtext($2))`, tenantID, ruleID); err != nil {
		return core.DetectionContent{}, err
	}
	var state string
	if err := tx.QueryRow(ctx, `SELECT state FROM detection_rule_versions WHERE tenant_id=$1 AND rule_id=$2 AND version=$3 FOR UPDATE`, tenantID, ruleID, version).Scan(&state); errors.Is(err, pgx.ErrNoRows) {
		return core.DetectionContent{}, ErrNotFound
	} else if err != nil {
		return core.DetectionContent{}, err
	}
	if state != "VALIDATED" {
		return core.DetectionContent{}, fmt.Errorf("%w: only VALIDATED content can be published", ErrVersionConflict)
	}
	now := time.Now().UTC()
	if _, err := tx.Exec(ctx, `UPDATE detection_rule_versions SET state='SUPERSEDED',updated_at=$3 WHERE tenant_id=$1 AND rule_id=$2 AND state='PUBLISHED'`, tenantID, ruleID, now); err != nil {
		return core.DetectionContent{}, err
	}
	if _, err := tx.Exec(ctx, `UPDATE detection_rule_versions SET state='PUBLISHED',published_at=$4,updated_at=$4 WHERE tenant_id=$1 AND rule_id=$2 AND version=$3`, tenantID, ruleID, version, now); err != nil {
		return core.DetectionContent{}, err
	}
	content, err := scanDetectionContent(tx.QueryRow(ctx, detectionContentSelect+` WHERE tenant_id=$1 AND rule_id=$2 AND version=$3`, tenantID, ruleID, version))
	if err != nil {
		return core.DetectionContent{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return core.DetectionContent{}, err
	}
	return content, nil
}

func (p *Postgres) DisableDetectionContent(ctx context.Context, tenantID, ruleID string) (core.DetectionContent, error) {
	content, err := scanDetectionContent(p.pool.QueryRow(ctx, `UPDATE detection_rule_versions SET state='DISABLED',updated_at=$3
		WHERE tenant_id=$1 AND rule_id=$2 AND state='PUBLISHED'
		RETURNING tenant_id,rule_id,version,state,sigma_yaml,positive_tests,negative_tests,rule_metadata,validation_report,
		 performance_budget_micros,created_by,created_at,updated_at,published_at`, tenantID, ruleID, time.Now().UTC()))
	if errors.Is(err, pgx.ErrNoRows) {
		return core.DetectionContent{}, ErrNotFound
	}
	if err != nil {
		return core.DetectionContent{}, fmt.Errorf("disable detection content: %w", err)
	}
	return content, nil
}

func (p *Postgres) RollbackDetectionContent(ctx context.Context, tenantID, ruleID string) (core.DetectionContent, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return core.DetectionContent{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1),hashtext($2))`, tenantID, ruleID); err != nil {
		return core.DetectionContent{}, err
	}
	var currentVersion, targetVersion string
	if err := tx.QueryRow(ctx, `SELECT version FROM detection_rule_versions WHERE tenant_id=$1 AND rule_id=$2 AND state='PUBLISHED' FOR UPDATE`, tenantID, ruleID).Scan(&currentVersion); errors.Is(err, pgx.ErrNoRows) {
		return core.DetectionContent{}, ErrNotFound
	} else if err != nil {
		return core.DetectionContent{}, err
	}
	if err := tx.QueryRow(ctx, `SELECT version FROM detection_rule_versions WHERE tenant_id=$1 AND rule_id=$2 AND state='SUPERSEDED' ORDER BY published_at DESC NULLS LAST,updated_at DESC LIMIT 1 FOR UPDATE`, tenantID, ruleID).Scan(&targetVersion); errors.Is(err, pgx.ErrNoRows) {
		return core.DetectionContent{}, ErrNotFound
	} else if err != nil {
		return core.DetectionContent{}, err
	}
	now := time.Now().UTC()
	if _, err := tx.Exec(ctx, `UPDATE detection_rule_versions SET state='SUPERSEDED',updated_at=$4 WHERE tenant_id=$1 AND rule_id=$2 AND version=$3`, tenantID, ruleID, currentVersion, now); err != nil {
		return core.DetectionContent{}, err
	}
	if _, err := tx.Exec(ctx, `UPDATE detection_rule_versions SET state='PUBLISHED',published_at=$4,updated_at=$4 WHERE tenant_id=$1 AND rule_id=$2 AND version=$3`, tenantID, ruleID, targetVersion, now); err != nil {
		return core.DetectionContent{}, err
	}
	content, err := scanDetectionContent(tx.QueryRow(ctx, detectionContentSelect+` WHERE tenant_id=$1 AND rule_id=$2 AND version=$3`, tenantID, ruleID, targetVersion))
	if err != nil {
		return core.DetectionContent{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return core.DetectionContent{}, err
	}
	return content, nil
}

const detectionContentSelect = `SELECT tenant_id,rule_id,version,state,sigma_yaml,positive_tests,negative_tests,
	rule_metadata,validation_report,performance_budget_micros,created_by,created_at,updated_at,published_at FROM detection_rule_versions`

type detectionScanner interface{ Scan(...interface{}) error }

func scanDetectionContent(scanner detectionScanner) (core.DetectionContent, error) {
	var content core.DetectionContent
	var positive, negative, rule, validation []byte
	if err := scanner.Scan(&content.TenantID, &content.RuleID, &content.Version, &content.State, &content.SigmaYAML,
		&positive, &negative, &rule, &validation, &content.PerformanceBudgetMicros, &content.CreatedBy,
		&content.CreatedAt, &content.UpdatedAt, &content.PublishedAt); err != nil {
		return core.DetectionContent{}, err
	}
	if err := json.Unmarshal(positive, &content.PositiveTests); err != nil {
		return core.DetectionContent{}, err
	}
	if err := json.Unmarshal(negative, &content.NegativeTests); err != nil {
		return core.DetectionContent{}, err
	}
	if err := json.Unmarshal(rule, &content.Rule); err != nil {
		return core.DetectionContent{}, err
	}
	if err := json.Unmarshal(validation, &content.Validation); err != nil {
		return core.DetectionContent{}, err
	}
	return content, nil
}

func collectDetectionRows(rows pgx.Rows) ([]core.DetectionContent, error) {
	items := []core.DetectionContent{}
	for rows.Next() {
		item, err := scanDetectionContent(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}
