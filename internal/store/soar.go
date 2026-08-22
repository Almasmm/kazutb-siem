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
	"github.com/kcsp/platform/internal/soar"
)

const soarPlaybookColumns = `tenant_id,playbook_id,name,description,state,latest_version,published_version,
	revision,created_by,updated_by,created_at,updated_at`

const soarVersionColumns = `tenant_id,playbook_id,version,state,spec,spec_hash,validation,created_by,
	created_at,validated_at,published_at`

const soarExecutionColumns = `tenant_id,execution_id,playbook_id,playbook_version,request_id,trigger_type,
	trigger_resource_type,trigger_resource_id,context,status,version,triggered_by,created_at,updated_at,
	started_at,completed_at`

const soarNodeColumns = `tenant_id,node_execution_id,execution_id,node_id,node_type,node_name,depends_on,
	config,status,attempt,available_at,output,error_code,error_detail,lease_owner,lease_until,started_at,
	completed_at,created_at,updated_at`

func (p *Postgres) CreateSOARPlaybook(ctx context.Context, playbook core.SOARPlaybook, version core.SOARPlaybookVersion) (core.SOARPlaybookDetails, error) {
	spec, validation, err := encodeSOARVersion(version)
	if err != nil {
		return core.SOARPlaybookDetails{}, err
	}
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return core.SOARPlaybookDetails{}, fmt.Errorf("begin SOAR playbook creation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `INSERT INTO soar_playbooks(
		tenant_id,playbook_id,name,description,state,latest_version,published_version,revision,
		created_by,updated_by,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		playbook.TenantID, playbook.ID, playbook.Name, playbook.Description, playbook.State,
		playbook.LatestVersion, playbook.PublishedVersion, playbook.Revision, playbook.CreatedBy,
		playbook.UpdatedBy, playbook.CreatedAt, playbook.UpdatedAt); err != nil {
		var postgresError *pgconn.PgError
		if errors.As(err, &postgresError) && postgresError.Code == "23505" {
			return core.SOARPlaybookDetails{}, ErrAlreadyExists
		}
		return core.SOARPlaybookDetails{}, fmt.Errorf("insert SOAR playbook: %w", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO soar_playbook_versions(
		tenant_id,playbook_id,version,state,spec,spec_hash,validation,created_by,created_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, version.TenantID, version.PlaybookID, version.Version,
		version.State, spec, version.SpecHash, validation, version.CreatedBy, version.CreatedAt); err != nil {
		return core.SOARPlaybookDetails{}, fmt.Errorf("insert SOAR playbook version: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return core.SOARPlaybookDetails{}, fmt.Errorf("commit SOAR playbook creation: %w", err)
	}
	return core.SOARPlaybookDetails{Playbook: playbook, Versions: []core.SOARPlaybookVersion{version}}, nil
}

func (p *Postgres) CreateSOARPlaybookVersion(ctx context.Context, tenantID, playbookID, actor string, spec core.SOARPlaybookSpec, report core.SOARValidationReport) (core.SOARPlaybookVersion, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return core.SOARPlaybookVersion{}, fmt.Errorf("begin SOAR version creation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", tenantID+"|"+playbookID); err != nil {
		return core.SOARPlaybookVersion{}, fmt.Errorf("lock SOAR playbook: %w", err)
	}
	var latest int
	if err := tx.QueryRow(ctx, "SELECT latest_version FROM soar_playbooks WHERE tenant_id=$1 AND playbook_id=$2 FOR UPDATE", tenantID, playbookID).Scan(&latest); errors.Is(err, pgx.ErrNoRows) {
		return core.SOARPlaybookVersion{}, ErrNotFound
	} else if err != nil {
		return core.SOARPlaybookVersion{}, fmt.Errorf("lock SOAR playbook row: %w", err)
	}
	now := time.Now().UTC()
	version := core.SOARPlaybookVersion{
		TenantID: tenantID, PlaybookID: playbookID, Version: latest + 1, State: core.SOARVersionDraft,
		Spec: spec, SpecHash: report.SpecHash, Validation: report, CreatedBy: actor, CreatedAt: now,
	}
	specPayload, validation, err := encodeSOARVersion(version)
	if err != nil {
		return core.SOARPlaybookVersion{}, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO soar_playbook_versions(
		tenant_id,playbook_id,version,state,spec,spec_hash,validation,created_by,created_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, tenantID, playbookID, version.Version, version.State,
		specPayload, version.SpecHash, validation, actor, now); err != nil {
		return core.SOARPlaybookVersion{}, fmt.Errorf("insert SOAR playbook version: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE soar_playbooks SET latest_version=$3,revision=revision+1,
		updated_by=$4,updated_at=$5 WHERE tenant_id=$1 AND playbook_id=$2`,
		tenantID, playbookID, version.Version, actor, now); err != nil {
		return core.SOARPlaybookVersion{}, fmt.Errorf("update SOAR latest version: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return core.SOARPlaybookVersion{}, fmt.Errorf("commit SOAR version creation: %w", err)
	}
	return version, nil
}

func (p *Postgres) GetSOARPlaybook(ctx context.Context, tenantID, playbookID string) (core.SOARPlaybookDetails, error) {
	playbook, err := scanSOARPlaybook(p.pool.QueryRow(ctx, "SELECT "+soarPlaybookColumns+" FROM soar_playbooks WHERE tenant_id=$1 AND playbook_id=$2", tenantID, playbookID))
	if errors.Is(err, pgx.ErrNoRows) {
		return core.SOARPlaybookDetails{}, ErrNotFound
	}
	if err != nil {
		return core.SOARPlaybookDetails{}, fmt.Errorf("get SOAR playbook: %w", err)
	}
	rows, err := p.pool.Query(ctx, "SELECT "+soarVersionColumns+" FROM soar_playbook_versions WHERE tenant_id=$1 AND playbook_id=$2 ORDER BY version DESC", tenantID, playbookID)
	if err != nil {
		return core.SOARPlaybookDetails{}, fmt.Errorf("list SOAR playbook versions: %w", err)
	}
	defer rows.Close()
	versions := []core.SOARPlaybookVersion{}
	for rows.Next() {
		version, scanErr := scanSOARVersion(rows)
		if scanErr != nil {
			return core.SOARPlaybookDetails{}, fmt.Errorf("scan SOAR playbook version: %w", scanErr)
		}
		versions = append(versions, version)
	}
	if err := rows.Err(); err != nil {
		return core.SOARPlaybookDetails{}, fmt.Errorf("iterate SOAR versions: %w", err)
	}
	return core.SOARPlaybookDetails{Playbook: playbook, Versions: versions}, nil
}

func (p *Postgres) ListSOARPlaybooks(ctx context.Context, tenantID string) ([]core.SOARPlaybook, error) {
	rows, err := p.pool.Query(ctx, "SELECT "+soarPlaybookColumns+" FROM soar_playbooks WHERE tenant_id=$1 ORDER BY updated_at DESC,playbook_id", tenantID)
	if err != nil {
		return nil, fmt.Errorf("list SOAR playbooks: %w", err)
	}
	defer rows.Close()
	items := []core.SOARPlaybook{}
	for rows.Next() {
		playbook, scanErr := scanSOARPlaybook(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("scan SOAR playbook: %w", scanErr)
		}
		items = append(items, playbook)
	}
	return items, rows.Err()
}

func (p *Postgres) SaveSOARValidation(ctx context.Context, tenantID, playbookID string, version int, report core.SOARValidationReport) (core.SOARPlaybookVersion, error) {
	validation, err := json.Marshal(report)
	if err != nil {
		return core.SOARPlaybookVersion{}, fmt.Errorf("encode SOAR validation report: %w", err)
	}
	state := core.SOARVersionDraft
	var validatedAt *time.Time
	if report.Valid {
		state = core.SOARVersionValidated
		value := report.ValidatedAt.UTC()
		validatedAt = &value
	}
	item, err := scanSOARVersion(p.pool.QueryRow(ctx, `UPDATE soar_playbook_versions SET
		state=$4,validation=$5,spec_hash=$6,validated_at=$7
		WHERE tenant_id=$1 AND playbook_id=$2 AND version=$3 AND state IN ('DRAFT','VALIDATED')
		RETURNING `+soarVersionColumns, tenantID, playbookID, version, state, validation, report.SpecHash, validatedAt))
	if errors.Is(err, pgx.ErrNoRows) {
		return core.SOARPlaybookVersion{}, soar.ErrInvalidState
	}
	if err != nil {
		return core.SOARPlaybookVersion{}, fmt.Errorf("save SOAR validation report: %w", err)
	}
	return item, nil
}

func (p *Postgres) PublishSOARPlaybookVersion(ctx context.Context, tenantID, playbookID string, version int, actor string) (core.SOARPlaybookDetails, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return core.SOARPlaybookDetails{}, fmt.Errorf("begin SOAR publish: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var state string
	if err := tx.QueryRow(ctx, `SELECT state FROM soar_playbook_versions
		WHERE tenant_id=$1 AND playbook_id=$2 AND version=$3 FOR UPDATE`, tenantID, playbookID, version).Scan(&state); errors.Is(err, pgx.ErrNoRows) {
		return core.SOARPlaybookDetails{}, ErrNotFound
	} else if err != nil {
		return core.SOARPlaybookDetails{}, fmt.Errorf("lock SOAR version: %w", err)
	}
	if state != core.SOARVersionValidated {
		return core.SOARPlaybookDetails{}, soar.ErrInvalidState
	}
	now := time.Now().UTC()
	if _, err := tx.Exec(ctx, `UPDATE soar_playbook_versions SET state='RETIRED'
		WHERE tenant_id=$1 AND playbook_id=$2 AND state='PUBLISHED'`, tenantID, playbookID); err != nil {
		return core.SOARPlaybookDetails{}, fmt.Errorf("retire previous SOAR version: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE soar_playbook_versions SET state='PUBLISHED',published_at=$4
		WHERE tenant_id=$1 AND playbook_id=$2 AND version=$3`, tenantID, playbookID, version, now); err != nil {
		return core.SOARPlaybookDetails{}, fmt.Errorf("publish SOAR version: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE soar_playbooks SET state='PUBLISHED',published_version=$3,
		revision=revision+1,updated_by=$4,updated_at=$5 WHERE tenant_id=$1 AND playbook_id=$2`,
		tenantID, playbookID, version, actor, now); err != nil {
		return core.SOARPlaybookDetails{}, fmt.Errorf("publish SOAR playbook: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return core.SOARPlaybookDetails{}, fmt.Errorf("commit SOAR publish: %w", err)
	}
	return p.GetSOARPlaybook(ctx, tenantID, playbookID)
}

func (p *Postgres) DisableSOARPlaybook(ctx context.Context, tenantID, playbookID, actor string) (core.SOARPlaybook, error) {
	item, err := scanSOARPlaybook(p.pool.QueryRow(ctx, `UPDATE soar_playbooks SET state='DISABLED',
		revision=revision+1,updated_by=$3,updated_at=$4 WHERE tenant_id=$1 AND playbook_id=$2
		RETURNING `+soarPlaybookColumns, tenantID, playbookID, actor, time.Now().UTC()))
	if errors.Is(err, pgx.ErrNoRows) {
		return core.SOARPlaybook{}, ErrNotFound
	}
	if err != nil {
		return core.SOARPlaybook{}, fmt.Errorf("disable SOAR playbook: %w", err)
	}
	return item, nil
}

func (p *Postgres) CreateSOARExecution(ctx context.Context, execution core.SOARExecution, nodes []core.SOARNode) (core.SOARExecution, bool, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return core.SOARExecution{}, false, fmt.Errorf("begin SOAR execution creation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", execution.TenantID+"|"+execution.RequestID); err != nil {
		return core.SOARExecution{}, false, fmt.Errorf("lock SOAR request id: %w", err)
	}
	var existingID string
	err = tx.QueryRow(ctx, "SELECT execution_id FROM soar_executions WHERE tenant_id=$1 AND request_id=$2", execution.TenantID, execution.RequestID).Scan(&existingID)
	if err == nil {
		_ = tx.Rollback(ctx)
		existing, getErr := p.GetSOARExecution(ctx, execution.TenantID, existingID)
		return existing, false, getErr
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return core.SOARExecution{}, false, fmt.Errorf("check SOAR execution idempotency: %w", err)
	}
	var publishedState, versionState string
	err = tx.QueryRow(ctx, `SELECT p.state,v.state FROM soar_playbooks p
		JOIN soar_playbook_versions v ON v.tenant_id=p.tenant_id AND v.playbook_id=p.playbook_id
			AND v.version=$3
		WHERE p.tenant_id=$1 AND p.playbook_id=$2 FOR UPDATE`,
		execution.TenantID, execution.PlaybookID, execution.PlaybookVersion).Scan(&publishedState, &versionState)
	if errors.Is(err, pgx.ErrNoRows) {
		return core.SOARExecution{}, false, ErrNotFound
	}
	if err != nil {
		return core.SOARExecution{}, false, fmt.Errorf("validate SOAR execution version: %w", err)
	}
	if publishedState != core.SOARPlaybookPublished || versionState != core.SOARVersionPublished {
		return core.SOARExecution{}, false, soar.ErrInvalidState
	}
	contextPayload, err := json.Marshal(execution.Context)
	if err != nil {
		return core.SOARExecution{}, false, fmt.Errorf("encode SOAR execution context: %w", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO soar_executions(
		tenant_id,execution_id,playbook_id,playbook_version,request_id,trigger_type,trigger_resource_type,
		trigger_resource_id,context,status,version,triggered_by,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
		execution.TenantID, execution.ID, execution.PlaybookID, execution.PlaybookVersion, execution.RequestID,
		execution.TriggerType, execution.TriggerResourceType, execution.TriggerResourceID, contextPayload,
		execution.Status, execution.Version, execution.TriggeredBy, execution.CreatedAt, execution.UpdatedAt); err != nil {
		return core.SOARExecution{}, false, fmt.Errorf("insert SOAR execution: %w", err)
	}
	for _, node := range nodes {
		dependencies := node.DependsOn
		if dependencies == nil {
			dependencies = []string{}
		}
		nodeConfig := node.Config
		if nodeConfig == nil {
			nodeConfig = map[string]interface{}{}
		}
		dependsOn, _ := json.Marshal(dependencies)
		config, _ := json.Marshal(nodeConfig)
		status := "PENDING"
		if len(node.DependsOn) == 0 {
			status = "READY"
		}
		if _, err := tx.Exec(ctx, `INSERT INTO soar_node_executions(
			tenant_id,node_execution_id,execution_id,node_id,node_type,node_name,depends_on,config,status,
			attempt,available_at,created_at,updated_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,0,$10,$10,$10)`,
			execution.TenantID, core.NewID("snx"), execution.ID, node.ID, node.Type, node.Name,
			dependsOn, config, status, execution.CreatedAt); err != nil {
			return core.SOARExecution{}, false, fmt.Errorf("insert SOAR node snapshot %s: %w", node.ID, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return core.SOARExecution{}, false, fmt.Errorf("commit SOAR execution creation: %w", err)
	}
	stored, err := p.GetSOARExecution(ctx, execution.TenantID, execution.ID)
	return stored, true, err
}

func (p *Postgres) GetSOARExecution(ctx context.Context, tenantID, executionID string) (core.SOARExecution, error) {
	item, err := scanSOARExecution(p.pool.QueryRow(ctx, "SELECT "+soarExecutionColumns+" FROM soar_executions WHERE tenant_id=$1 AND execution_id=$2", tenantID, executionID))
	if errors.Is(err, pgx.ErrNoRows) {
		return core.SOARExecution{}, ErrNotFound
	}
	if err != nil {
		return core.SOARExecution{}, fmt.Errorf("get SOAR execution: %w", err)
	}
	nodes, err := p.listSOARNodeExecutions(ctx, tenantID, executionID)
	if err != nil {
		return core.SOARExecution{}, err
	}
	item.Nodes = nodes
	return item, nil
}

func (p *Postgres) ListSOARExecutions(ctx context.Context, tenantID string, filter core.SOARExecutionFilter) ([]core.SOARExecution, error) {
	if filter.Limit <= 0 || filter.Limit > 500 {
		filter.Limit = 100
	}
	rows, err := p.pool.Query(ctx, `SELECT `+soarExecutionColumns+` FROM soar_executions
		WHERE tenant_id=$1 AND ($2='' OR playbook_id=$2) AND ($3='' OR status=$3)
		ORDER BY created_at DESC,execution_id LIMIT $4`, tenantID, filter.PlaybookID, filter.Status, filter.Limit)
	if err != nil {
		return nil, fmt.Errorf("list SOAR executions: %w", err)
	}
	defer rows.Close()
	items := []core.SOARExecution{}
	for rows.Next() {
		item, scanErr := scanSOARExecution(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("scan SOAR execution: %w", scanErr)
		}
		nodes, nodeErr := p.listSOARNodeExecutions(ctx, tenantID, item.ID)
		if nodeErr != nil {
			return nil, nodeErr
		}
		item.Nodes = nodes
		items = append(items, item)
	}
	return items, rows.Err()
}

func (p *Postgres) listSOARNodeExecutions(ctx context.Context, tenantID, executionID string) ([]core.SOARNodeExecution, error) {
	rows, err := p.pool.Query(ctx, "SELECT "+soarNodeColumns+" FROM soar_node_executions WHERE tenant_id=$1 AND execution_id=$2 ORDER BY created_at,node_id", tenantID, executionID)
	if err != nil {
		return nil, fmt.Errorf("list SOAR node executions: %w", err)
	}
	defer rows.Close()
	nodes := []core.SOARNodeExecution{}
	for rows.Next() {
		node, scanErr := scanSOARNodeExecution(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("scan SOAR node execution: %w", scanErr)
		}
		nodes = append(nodes, node)
	}
	return nodes, rows.Err()
}

func encodeSOARVersion(version core.SOARPlaybookVersion) ([]byte, []byte, error) {
	spec, err := json.Marshal(version.Spec)
	if err != nil {
		return nil, nil, fmt.Errorf("encode SOAR playbook spec: %w", err)
	}
	validation, err := json.Marshal(version.Validation)
	if err != nil {
		return nil, nil, fmt.Errorf("encode SOAR validation report: %w", err)
	}
	return spec, validation, nil
}

func scanSOARPlaybook(row threatRow) (core.SOARPlaybook, error) {
	var item core.SOARPlaybook
	err := row.Scan(&item.TenantID, &item.ID, &item.Name, &item.Description, &item.State,
		&item.LatestVersion, &item.PublishedVersion, &item.Revision, &item.CreatedBy, &item.UpdatedBy,
		&item.CreatedAt, &item.UpdatedAt)
	return item, err
}

func scanSOARVersion(row threatRow) (core.SOARPlaybookVersion, error) {
	var item core.SOARPlaybookVersion
	var spec, validation []byte
	err := row.Scan(&item.TenantID, &item.PlaybookID, &item.Version, &item.State, &spec,
		&item.SpecHash, &validation, &item.CreatedBy, &item.CreatedAt, &item.ValidatedAt, &item.PublishedAt)
	if err != nil {
		return core.SOARPlaybookVersion{}, err
	}
	if err := json.Unmarshal(spec, &item.Spec); err != nil {
		return core.SOARPlaybookVersion{}, fmt.Errorf("decode SOAR playbook spec: %w", err)
	}
	if err := json.Unmarshal(validation, &item.Validation); err != nil {
		return core.SOARPlaybookVersion{}, fmt.Errorf("decode SOAR validation report: %w", err)
	}
	return item, nil
}

func scanSOARExecution(row threatRow) (core.SOARExecution, error) {
	var item core.SOARExecution
	var contextPayload []byte
	err := row.Scan(&item.TenantID, &item.ID, &item.PlaybookID, &item.PlaybookVersion, &item.RequestID,
		&item.TriggerType, &item.TriggerResourceType, &item.TriggerResourceID, &contextPayload, &item.Status,
		&item.Version, &item.TriggeredBy, &item.CreatedAt, &item.UpdatedAt, &item.StartedAt, &item.CompletedAt)
	if err != nil {
		return core.SOARExecution{}, err
	}
	if err := json.Unmarshal(contextPayload, &item.Context); err != nil {
		return core.SOARExecution{}, fmt.Errorf("decode SOAR execution context: %w", err)
	}
	item.Nodes = []core.SOARNodeExecution{}
	return item, nil
}

func scanSOARNodeExecution(row threatRow) (core.SOARNodeExecution, error) {
	var item core.SOARNodeExecution
	var dependsOn, config, output []byte
	err := row.Scan(&item.TenantID, &item.ID, &item.ExecutionID, &item.NodeID, &item.NodeType,
		&item.NodeName, &dependsOn, &config, &item.Status, &item.Attempt, &item.AvailableAt, &output,
		&item.ErrorCode, &item.ErrorDetail, &item.LeaseOwner, &item.LeaseUntil, &item.StartedAt,
		&item.CompletedAt, &item.CreatedAt, &item.UpdatedAt)
	if err != nil {
		return core.SOARNodeExecution{}, err
	}
	if err := json.Unmarshal(dependsOn, &item.DependsOn); err != nil {
		return core.SOARNodeExecution{}, fmt.Errorf("decode SOAR node dependencies: %w", err)
	}
	if err := json.Unmarshal(config, &item.Config); err != nil {
		return core.SOARNodeExecution{}, fmt.Errorf("decode SOAR node configuration: %w", err)
	}
	if err := json.Unmarshal(output, &item.Output); err != nil {
		return core.SOARNodeExecution{}, fmt.Errorf("decode SOAR node output: %w", err)
	}
	return item, nil
}

func normalizeSOARStatus(value string) string {
	return strings.ToUpper(strings.TrimSpace(value))
}
