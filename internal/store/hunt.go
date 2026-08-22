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

type HuntStore interface {
	HuntEvents(context.Context, string, core.HuntRequest) (core.HuntPage, error)
	CreateSavedHunt(context.Context, core.SavedHunt) (core.SavedHunt, error)
	ListSavedHunts(context.Context, string, string, bool) ([]core.SavedHunt, error)
	SavedHunt(context.Context, string, string, string, bool) (core.SavedHunt, error)
	UpdateSavedHunt(context.Context, core.SavedHunt, string, bool) (core.SavedHunt, error)
	DeleteSavedHunt(context.Context, string, string, int, string, bool) error
	RecordHuntExecution(context.Context, core.HuntExecution) error
	ListHuntExecutions(context.Context, string, string, string, bool, int) ([]core.HuntExecution, error)
}

func (p *Postgres) CreateSavedHunt(ctx context.Context, hunt core.SavedHunt) (core.SavedHunt, error) {
	hunt.Name = strings.TrimSpace(hunt.Name)
	hunt.Description = strings.TrimSpace(hunt.Description)
	hunt.Visibility = strings.ToUpper(strings.TrimSpace(hunt.Visibility))
	if hunt.ID == "" {
		hunt.ID = core.NewID("hunt")
	}
	if hunt.TenantID == "" || hunt.Name == "" || len(hunt.Name) > 160 || len(hunt.Description) > 4000 || hunt.Owner == "" {
		return core.SavedHunt{}, fmt.Errorf("create saved hunt: required fields are missing or too large")
	}
	if hunt.Visibility == "" {
		hunt.Visibility = "PRIVATE"
	}
	if hunt.Visibility != "PRIVATE" && hunt.Visibility != "TENANT" {
		return core.SavedHunt{}, fmt.Errorf("create saved hunt: visibility must be PRIVATE or TENANT")
	}
	query, err := json.Marshal(hunt.Query)
	if err != nil {
		return core.SavedHunt{}, err
	}
	now := time.Now().UTC()
	created, err := scanSavedHunt(p.pool.QueryRow(ctx, `INSERT INTO saved_hunts(
		tenant_id,hunt_id,name,description,visibility,query,owner,version,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,1,$8,$8)
		RETURNING tenant_id,hunt_id,name,description,visibility,query,owner,version,created_at,updated_at`,
		hunt.TenantID, hunt.ID, hunt.Name, hunt.Description, hunt.Visibility, query, hunt.Owner, now))
	if err != nil {
		var postgresError *pgconn.PgError
		if errors.As(err, &postgresError) && postgresError.Code == "23505" {
			return core.SavedHunt{}, ErrAlreadyExists
		}
		return core.SavedHunt{}, fmt.Errorf("create saved hunt: %w", err)
	}
	return created, nil
}

func (p *Postgres) ListSavedHunts(ctx context.Context, tenantID, viewer string, includeAll bool) ([]core.SavedHunt, error) {
	rows, err := p.pool.Query(ctx, savedHuntSelect+` WHERE tenant_id=$1 AND deleted_at IS NULL
		AND (owner=$2 OR visibility='TENANT' OR $3::boolean) ORDER BY updated_at DESC,hunt_id`, tenantID, viewer, includeAll)
	if err != nil {
		return nil, fmt.Errorf("list saved hunts: %w", err)
	}
	defer rows.Close()
	items := []core.SavedHunt{}
	for rows.Next() {
		item, err := scanSavedHunt(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (p *Postgres) SavedHunt(ctx context.Context, tenantID, huntID, viewer string, includeAll bool) (core.SavedHunt, error) {
	item, err := scanSavedHunt(p.pool.QueryRow(ctx, savedHuntSelect+` WHERE tenant_id=$1 AND hunt_id=$2 AND deleted_at IS NULL
		AND (owner=$3 OR visibility='TENANT' OR $4::boolean)`, tenantID, huntID, viewer, includeAll))
	if errors.Is(err, pgx.ErrNoRows) {
		return core.SavedHunt{}, ErrNotFound
	}
	if err != nil {
		return core.SavedHunt{}, fmt.Errorf("get saved hunt: %w", err)
	}
	return item, nil
}

func (p *Postgres) UpdateSavedHunt(ctx context.Context, hunt core.SavedHunt, actor string, includeAll bool) (core.SavedHunt, error) {
	current, err := p.SavedHunt(ctx, hunt.TenantID, hunt.ID, actor, includeAll)
	if err != nil {
		return core.SavedHunt{}, err
	}
	if current.Owner != actor && !includeAll {
		return core.SavedHunt{}, ErrNotFound
	}
	if current.Version != hunt.Version {
		return core.SavedHunt{}, ErrVersionConflict
	}
	hunt.Name = strings.TrimSpace(hunt.Name)
	hunt.Description = strings.TrimSpace(hunt.Description)
	hunt.Visibility = strings.ToUpper(strings.TrimSpace(hunt.Visibility))
	if hunt.Name == "" || len(hunt.Name) > 160 || len(hunt.Description) > 4000 || (hunt.Visibility != "PRIVATE" && hunt.Visibility != "TENANT") {
		return core.SavedHunt{}, fmt.Errorf("update saved hunt: invalid name, description or visibility")
	}
	query, err := json.Marshal(hunt.Query)
	if err != nil {
		return core.SavedHunt{}, err
	}
	updated, err := scanSavedHunt(p.pool.QueryRow(ctx, `UPDATE saved_hunts SET name=$4,description=$5,visibility=$6,query=$7,
		version=version+1,updated_at=$8 WHERE tenant_id=$1 AND hunt_id=$2 AND version=$3 AND deleted_at IS NULL
		RETURNING tenant_id,hunt_id,name,description,visibility,query,owner,version,created_at,updated_at`,
		hunt.TenantID, hunt.ID, hunt.Version, hunt.Name, hunt.Description, hunt.Visibility, query, time.Now().UTC()))
	if errors.Is(err, pgx.ErrNoRows) {
		return core.SavedHunt{}, ErrVersionConflict
	}
	if err != nil {
		var postgresError *pgconn.PgError
		if errors.As(err, &postgresError) && postgresError.Code == "23505" {
			return core.SavedHunt{}, ErrAlreadyExists
		}
		return core.SavedHunt{}, fmt.Errorf("update saved hunt: %w", err)
	}
	return updated, nil
}

func (p *Postgres) DeleteSavedHunt(ctx context.Context, tenantID, huntID string, version int, actor string, includeAll bool) error {
	current, err := p.SavedHunt(ctx, tenantID, huntID, actor, includeAll)
	if err != nil {
		return err
	}
	if current.Owner != actor && !includeAll {
		return ErrNotFound
	}
	if current.Version != version {
		return ErrVersionConflict
	}
	tag, err := p.pool.Exec(ctx, `UPDATE saved_hunts SET deleted_at=$4,updated_at=$4,version=version+1
		WHERE tenant_id=$1 AND hunt_id=$2 AND version=$3 AND deleted_at IS NULL`, tenantID, huntID, version, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("delete saved hunt: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrVersionConflict
	}
	return nil
}

func (p *Postgres) RecordHuntExecution(ctx context.Context, execution core.HuntExecution) error {
	if execution.ID == "" {
		execution.ID = core.NewID("hex")
	}
	if execution.CreatedAt.IsZero() {
		execution.CreatedAt = time.Now().UTC()
	}
	query, err := json.Marshal(execution.Query)
	if err != nil {
		return err
	}
	_, err = p.pool.Exec(ctx, `INSERT INTO hunt_executions(
		tenant_id,execution_id,saved_hunt_id,actor,query,query_hash,status,returned,duration_micros,error,created_at)
		VALUES($1,$2,NULLIF($3,''),$4,$5,$6,$7,$8,$9,$10,$11)`, execution.TenantID, execution.ID, execution.SavedHuntID,
		execution.Actor, query, execution.QueryHash, execution.Status, execution.Returned, execution.DurationMicros, execution.Error, execution.CreatedAt)
	if err != nil {
		return fmt.Errorf("record hunt execution: %w", err)
	}
	return nil
}

func (p *Postgres) ListHuntExecutions(ctx context.Context, tenantID, savedHuntID, viewer string, includeAll bool, limit int) ([]core.HuntExecution, error) {
	limit = normalizedLimit(limit)
	rows, err := p.pool.Query(ctx, `SELECT tenant_id,execution_id,COALESCE(saved_hunt_id,''),actor,query,query_hash,status,
		returned,duration_micros,error,created_at FROM hunt_executions WHERE tenant_id=$1 AND ($2='' OR saved_hunt_id=$2)
		AND (actor=$3 OR $4::boolean) ORDER BY created_at DESC LIMIT $5`, tenantID, savedHuntID, viewer, includeAll, limit)
	if err != nil {
		return nil, fmt.Errorf("list hunt executions: %w", err)
	}
	defer rows.Close()
	items := []core.HuntExecution{}
	for rows.Next() {
		var item core.HuntExecution
		var query []byte
		if err := rows.Scan(&item.TenantID, &item.ID, &item.SavedHuntID, &item.Actor, &query, &item.QueryHash, &item.Status,
			&item.Returned, &item.DurationMicros, &item.Error, &item.CreatedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(query, &item.Query); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

const savedHuntSelect = `SELECT tenant_id,hunt_id,name,description,visibility,query,owner,version,created_at,updated_at FROM saved_hunts`

func scanSavedHunt(scanner detectionScanner) (core.SavedHunt, error) {
	var item core.SavedHunt
	var query []byte
	if err := scanner.Scan(&item.TenantID, &item.ID, &item.Name, &item.Description, &item.Visibility, &query, &item.Owner,
		&item.Version, &item.CreatedAt, &item.UpdatedAt); err != nil {
		return core.SavedHunt{}, err
	}
	if err := json.Unmarshal(query, &item.Query); err != nil {
		return core.SavedHunt{}, err
	}
	return item, nil
}
