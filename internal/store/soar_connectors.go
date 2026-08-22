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

const soarConnectorColumns = `tenant_id,connector_id,name,kind,state,endpoint,auth_type,secret_ref,
	allowed_actions,settings,timeout_seconds,retry_policy,rate_limit_per_minute,version,health_status,
	health_error_class,health_detail,last_tested_at,created_by,updated_by,created_at,updated_at`

const soarConnectorTestColumns = `tenant_id,test_id,connector_id,request_id,status,error_class,detail,
	http_status,latency_ms,tested_by,worker_id,attempt,lease_until,created_at,started_at,completed_at`

func (p *Postgres) CreateSOARConnector(ctx context.Context, connector core.SOARConnector) (core.SOARConnector, error) {
	actions, settings, retry, err := encodeSOARConnectorJSON(connector)
	if err != nil {
		return core.SOARConnector{}, err
	}
	item, err := scanSOARConnector(p.pool.QueryRow(ctx, `INSERT INTO soar_connectors(
		tenant_id,connector_id,name,kind,state,endpoint,auth_type,secret_ref,allowed_actions,settings,
		timeout_seconds,retry_policy,rate_limit_per_minute,version,health_status,health_error_class,
		health_detail,last_tested_at,created_by,updated_by,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)
		RETURNING `+soarConnectorColumns,
		connector.TenantID, connector.ID, connector.Name, connector.Kind, connector.State, connector.Endpoint,
		connector.AuthType, connector.SecretRef, actions, settings, connector.TimeoutSeconds, retry,
		connector.RateLimitPerMinute, connector.Version, connector.HealthStatus, connector.HealthErrorClass,
		connector.HealthDetail, connector.LastTestedAt, connector.CreatedBy, connector.UpdatedBy,
		connector.CreatedAt, connector.UpdatedAt))
	if err != nil {
		var postgresError *pgconn.PgError
		if errors.As(err, &postgresError) && postgresError.Code == "23505" {
			return core.SOARConnector{}, ErrAlreadyExists
		}
		return core.SOARConnector{}, fmt.Errorf("create SOAR connector: %w", err)
	}
	return item, nil
}

func (p *Postgres) GetSOARConnector(ctx context.Context, tenantID, connectorID string) (core.SOARConnector, error) {
	item, err := scanSOARConnector(p.pool.QueryRow(ctx, `SELECT `+soarConnectorColumns+`
		FROM soar_connectors WHERE tenant_id=$1 AND connector_id=$2`, tenantID, connectorID))
	if errors.Is(err, pgx.ErrNoRows) {
		return core.SOARConnector{}, ErrNotFound
	}
	if err != nil {
		return core.SOARConnector{}, fmt.Errorf("get SOAR connector: %w", err)
	}
	return item, nil
}

func (p *Postgres) ListSOARConnectors(ctx context.Context, tenantID string,
	filter core.SOARConnectorFilter) ([]core.SOARConnector, error) {
	if filter.Limit <= 0 || filter.Limit > 500 {
		filter.Limit = 100
	}
	rows, err := p.pool.Query(ctx, `SELECT `+soarConnectorColumns+` FROM soar_connectors
		WHERE tenant_id=$1 AND ($2='' OR kind=$2) AND ($3='' OR state=$3)
		ORDER BY updated_at DESC,connector_id LIMIT $4`, tenantID, filter.Kind, filter.State, filter.Limit)
	if err != nil {
		return nil, fmt.Errorf("list SOAR connectors: %w", err)
	}
	defer rows.Close()
	items := []core.SOARConnector{}
	for rows.Next() {
		item, scanErr := scanSOARConnector(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("scan SOAR connector: %w", scanErr)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (p *Postgres) UpdateSOARConnector(ctx context.Context, connector core.SOARConnector,
	expectedVersion int) (core.SOARConnector, error) {
	actions, settings, retry, err := encodeSOARConnectorJSON(connector)
	if err != nil {
		return core.SOARConnector{}, err
	}
	item, err := scanSOARConnector(p.pool.QueryRow(ctx, `UPDATE soar_connectors SET
		name=$4,kind=$5,state=$6,endpoint=$7,auth_type=$8,secret_ref=$9,allowed_actions=$10,
		settings=$11,timeout_seconds=$12,retry_policy=$13,rate_limit_per_minute=$14,
		version=version+1,health_status=$15,health_error_class='',health_detail='',
		last_tested_at=NULL,updated_by=$16,updated_at=$17
		WHERE tenant_id=$1 AND connector_id=$2 AND version=$3 AND state<>'DISABLED'
		RETURNING `+soarConnectorColumns,
		connector.TenantID, connector.ID, expectedVersion, connector.Name, connector.Kind, connector.State,
		connector.Endpoint, connector.AuthType, connector.SecretRef, actions, settings, connector.TimeoutSeconds,
		retry, connector.RateLimitPerMinute, connector.HealthStatus, connector.UpdatedBy, connector.UpdatedAt))
	if errors.Is(err, pgx.ErrNoRows) {
		if _, getErr := p.GetSOARConnector(ctx, connector.TenantID, connector.ID); errors.Is(getErr, ErrNotFound) {
			return core.SOARConnector{}, ErrNotFound
		}
		return core.SOARConnector{}, ErrVersionConflict
	}
	if err != nil {
		var postgresError *pgconn.PgError
		if errors.As(err, &postgresError) && postgresError.Code == "23505" {
			return core.SOARConnector{}, ErrAlreadyExists
		}
		return core.SOARConnector{}, fmt.Errorf("update SOAR connector: %w", err)
	}
	return item, nil
}

func (p *Postgres) DisableSOARConnector(ctx context.Context, tenantID, connectorID, actor string,
	expectedVersion int) (core.SOARConnector, error) {
	item, err := scanSOARConnector(p.pool.QueryRow(ctx, `UPDATE soar_connectors SET
		state='DISABLED',health_status='DISABLED',health_error_class='',health_detail='',
		version=version+1,updated_by=$4,updated_at=$5
		WHERE tenant_id=$1 AND connector_id=$2 AND version=$3 AND state<>'DISABLED'
		RETURNING `+soarConnectorColumns, tenantID, connectorID, expectedVersion, actor, time.Now().UTC()))
	if errors.Is(err, pgx.ErrNoRows) {
		if _, getErr := p.GetSOARConnector(ctx, tenantID, connectorID); errors.Is(getErr, ErrNotFound) {
			return core.SOARConnector{}, ErrNotFound
		}
		return core.SOARConnector{}, ErrVersionConflict
	}
	if err != nil {
		return core.SOARConnector{}, fmt.Errorf("disable SOAR connector: %w", err)
	}
	return item, nil
}

func (p *Postgres) CreateSOARConnectorTest(ctx context.Context,
	test core.SOARConnectorTest) (core.SOARConnectorTest, bool, error) {
	item, err := scanSOARConnectorTest(p.pool.QueryRow(ctx, `INSERT INTO soar_connector_tests(
		tenant_id,test_id,connector_id,request_id,status,tested_by,created_at)
		SELECT $1,$2,$3,$4,$5,$6,$7 FROM soar_connectors
		WHERE tenant_id=$1 AND connector_id=$3 AND state<>'DISABLED'
		ON CONFLICT (tenant_id,request_id) DO NOTHING
		RETURNING `+soarConnectorTestColumns,
		test.TenantID, test.ID, test.ConnectorID, test.RequestID, test.Status, test.TestedBy, test.CreatedAt))
	if err == nil {
		return item, true, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return core.SOARConnectorTest{}, false, fmt.Errorf("queue SOAR connector test: %w", err)
	}
	item, err = scanSOARConnectorTest(p.pool.QueryRow(ctx, `SELECT `+soarConnectorTestColumns+`
		FROM soar_connector_tests WHERE tenant_id=$1 AND request_id=$2`, test.TenantID, test.RequestID))
	if err == nil {
		return item, false, nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return core.SOARConnectorTest{}, false, ErrNotFound
	}
	return core.SOARConnectorTest{}, false, fmt.Errorf("load idempotent SOAR connector test: %w", err)
}

func (p *Postgres) ListSOARConnectorTests(ctx context.Context, tenantID, connectorID string,
	limit int) ([]core.SOARConnectorTest, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := p.pool.Query(ctx, `SELECT `+soarConnectorTestColumns+` FROM soar_connector_tests
		WHERE tenant_id=$1 AND connector_id=$2 ORDER BY created_at DESC,test_id LIMIT $3`,
		tenantID, connectorID, limit)
	if err != nil {
		return nil, fmt.Errorf("list SOAR connector tests: %w", err)
	}
	defer rows.Close()
	items := []core.SOARConnectorTest{}
	for rows.Next() {
		item, scanErr := scanSOARConnectorTest(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("scan SOAR connector test: %w", scanErr)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (p *Postgres) ClaimSOARConnectorTest(ctx context.Context, workerID, tenantScope string,
	lease time.Duration) (core.SOARConnectorTestWorkItem, bool, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return core.SOARConnectorTestWorkItem{}, false, fmt.Errorf("begin SOAR connector test claim: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	now := time.Now().UTC()
	var tenantID, testID string
	err = tx.QueryRow(ctx, `SELECT t.tenant_id,t.test_id FROM soar_connector_tests t
		JOIN soar_connectors c ON c.tenant_id=t.tenant_id AND c.connector_id=t.connector_id
		WHERE c.state<>'DISABLED' AND ($2='' OR t.tenant_id=$2)
		  AND (t.status='QUEUED' OR (t.status='RUNNING' AND COALESCE(t.lease_until,'-infinity'::timestamptz) <= $1))
		ORDER BY t.created_at,t.test_id FOR UPDATE OF t SKIP LOCKED LIMIT 1`,
		now, strings.TrimSpace(tenantScope)).Scan(&tenantID, &testID)
	if errors.Is(err, pgx.ErrNoRows) {
		return core.SOARConnectorTestWorkItem{}, false, nil
	}
	if err != nil {
		return core.SOARConnectorTestWorkItem{}, false, fmt.Errorf("select SOAR connector test: %w", err)
	}
	test, err := scanSOARConnectorTest(tx.QueryRow(ctx, `UPDATE soar_connector_tests SET
		status='RUNNING',worker_id=$3,attempt=attempt+1,lease_until=$4,
		started_at=COALESCE(started_at,$5)
		WHERE tenant_id=$1 AND test_id=$2 RETURNING `+soarConnectorTestColumns,
		tenantID, testID, workerID, now.Add(lease), now))
	if err != nil {
		return core.SOARConnectorTestWorkItem{}, false, fmt.Errorf("lease SOAR connector test: %w", err)
	}
	connector, err := scanSOARConnector(tx.QueryRow(ctx, `SELECT `+soarConnectorColumns+`
		FROM soar_connectors WHERE tenant_id=$1 AND connector_id=$2`, tenantID, test.ConnectorID))
	if err != nil {
		return core.SOARConnectorTestWorkItem{}, false, fmt.Errorf("load SOAR connector for test: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return core.SOARConnectorTestWorkItem{}, false, fmt.Errorf("commit SOAR connector test claim: %w", err)
	}
	return core.SOARConnectorTestWorkItem{Connector: connector, Test: test}, true, nil
}

func (p *Postgres) FinishSOARConnectorTest(ctx context.Context, tenantID, testID, workerID, status,
	errorClass, detail string, httpStatus int, latencyMS int64) (core.SOARConnectorTest, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return core.SOARConnectorTest{}, fmt.Errorf("begin SOAR connector test completion: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	now := time.Now().UTC()
	test, err := scanSOARConnectorTest(tx.QueryRow(ctx, `UPDATE soar_connector_tests SET
		status=$4,error_class=$5,detail=$6,http_status=$7,latency_ms=$8,
		worker_id=$3,lease_until=NULL,completed_at=$9
		WHERE tenant_id=$1 AND test_id=$2 AND status='RUNNING' AND worker_id=$3
		RETURNING `+soarConnectorTestColumns,
		tenantID, testID, workerID, status, errorClass, detail, httpStatus, latencyMS, now))
	if errors.Is(err, pgx.ErrNoRows) {
		return core.SOARConnectorTest{}, fmt.Errorf("%w: connector test lease changed", soar.ErrInvalidState)
	}
	if err != nil {
		return core.SOARConnectorTest{}, fmt.Errorf("complete SOAR connector test: %w", err)
	}
	state := core.SOARConnectorDegraded
	health := core.SOARConnectorHealthUnhealthy
	if status == core.SOARConnectorTestSucceeded {
		state = core.SOARConnectorReady
		health = core.SOARConnectorHealthHealthy
	}
	if status == core.SOARConnectorTestCredentials {
		state = core.SOARConnectorCredentialsNeeded
		health = core.SOARConnectorHealthCredentials
	}
	if _, err := tx.Exec(ctx, `UPDATE soar_connectors SET
		state=CASE WHEN state='DISABLED' THEN state ELSE $3 END,
		health_status=CASE WHEN state='DISABLED' THEN health_status ELSE $4 END,
		health_error_class=$5,health_detail=$6,last_tested_at=$7,
		version=version+1,updated_by=$8,updated_at=$7
		WHERE tenant_id=$1 AND connector_id=$2`,
		tenantID, test.ConnectorID, state, health, errorClass, detail, now, workerID); err != nil {
		return core.SOARConnectorTest{}, fmt.Errorf("update SOAR connector health: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return core.SOARConnectorTest{}, fmt.Errorf("commit SOAR connector test completion: %w", err)
	}
	return test, nil
}

func encodeSOARConnectorJSON(connector core.SOARConnector) ([]byte, []byte, []byte, error) {
	actions, err := json.Marshal(connector.AllowedActions)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("encode SOAR connector actions: %w", err)
	}
	settings, err := json.Marshal(connector.Settings)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("encode SOAR connector settings: %w", err)
	}
	retry, err := json.Marshal(connector.Retry)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("encode SOAR connector retry policy: %w", err)
	}
	return actions, settings, retry, nil
}

func scanSOARConnector(row threatRow) (core.SOARConnector, error) {
	var item core.SOARConnector
	var actions, settings, retry []byte
	err := row.Scan(&item.TenantID, &item.ID, &item.Name, &item.Kind, &item.State, &item.Endpoint,
		&item.AuthType, &item.SecretRef, &actions, &settings, &item.TimeoutSeconds, &retry,
		&item.RateLimitPerMinute, &item.Version, &item.HealthStatus, &item.HealthErrorClass,
		&item.HealthDetail, &item.LastTestedAt, &item.CreatedBy, &item.UpdatedBy, &item.CreatedAt, &item.UpdatedAt)
	if err != nil {
		return core.SOARConnector{}, err
	}
	if err := json.Unmarshal(actions, &item.AllowedActions); err != nil {
		return core.SOARConnector{}, fmt.Errorf("decode SOAR connector actions: %w", err)
	}
	if err := json.Unmarshal(settings, &item.Settings); err != nil {
		return core.SOARConnector{}, fmt.Errorf("decode SOAR connector settings: %w", err)
	}
	if err := json.Unmarshal(retry, &item.Retry); err != nil {
		return core.SOARConnector{}, fmt.Errorf("decode SOAR connector retry policy: %w", err)
	}
	return item, nil
}

func scanSOARConnectorTest(row threatRow) (core.SOARConnectorTest, error) {
	var item core.SOARConnectorTest
	err := row.Scan(&item.TenantID, &item.ID, &item.ConnectorID, &item.RequestID, &item.Status,
		&item.ErrorClass, &item.Detail, &item.HTTPStatus, &item.LatencyMS, &item.TestedBy,
		&item.WorkerID, &item.Attempt, &item.LeaseUntil, &item.CreatedAt, &item.StartedAt, &item.CompletedAt)
	return item, err
}
