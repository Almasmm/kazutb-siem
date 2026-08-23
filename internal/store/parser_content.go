package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kcsp/platform/internal/core"
)

type parserRow interface{ Scan(...any) error }

var ErrParserStateConflict = errors.New("parser state conflict")

func (p *Postgres) CreateParserDraft(ctx context.Context, content core.ParserContent) (core.ParserContent, error) {
	tx, err := p.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return core.ParserContent{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if content.RequestID != "" {
		existing, findErr := scanParserContent(tx.QueryRow(ctx, parserSelect+` WHERE tenant_id=$1 AND request_id=$2`, content.TenantID, content.RequestID))
		if findErr == nil {
			return existing, nil
		}
		if !errors.Is(findErr, pgx.ErrNoRows) {
			return core.ParserContent{}, findErr
		}
	}
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, content.TenantID+"|"+content.ParserID); err != nil {
		return core.ParserContent{}, err
	}
	if err = tx.QueryRow(ctx, `SELECT COALESCE(MAX(version),0)+1 FROM parser_versions WHERE tenant_id=$1 AND parser_id=$2`, content.TenantID, content.ParserID).Scan(&content.Version); err != nil {
		return core.ParserContent{}, err
	}
	spec, _ := json.Marshal(content.Spec)
	validation, _ := json.Marshal(content.Validation)
	now := time.Now().UTC()
	created, err := scanParserContent(tx.QueryRow(ctx, parserSelectInsert, content.TenantID, content.ParserID, content.Version, content.Name, core.ParserStateDraft, spec, validation, content.CreatedBy, content.RequestID, now, now))
	if err != nil {
		return core.ParserContent{}, fmt.Errorf("create parser draft: %w", err)
	}
	if err = tx.Commit(ctx); err != nil {
		return core.ParserContent{}, err
	}
	return created, nil
}

func (p *Postgres) ParserContent(ctx context.Context, tenantID, parserID string, version int) (core.ParserContent, error) {
	query := parserSelect + ` WHERE tenant_id=$1 AND parser_id=$2`
	args := []interface{}{tenantID, parserID}
	if version > 0 {
		query += ` AND version=$3`
		args = append(args, version)
	}
	query += ` ORDER BY version DESC LIMIT 1`
	content, err := scanParserContent(p.pool.QueryRow(ctx, query, args...))
	if errors.Is(err, pgx.ErrNoRows) {
		return core.ParserContent{}, ErrNotFound
	}
	return content, err
}

func (p *Postgres) ListParserContent(ctx context.Context, tenantID string) ([]core.ParserContent, error) {
	rows, err := p.pool.Query(ctx, parserSelect+` WHERE tenant_id=$1 ORDER BY updated_at DESC,parser_id,version DESC`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []core.ParserContent{}
	for rows.Next() {
		item, scanErr := scanParserContent(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (p *Postgres) SaveParserValidation(ctx context.Context, content core.ParserContent) (core.ParserContent, error) {
	validation, _ := json.Marshal(content.Validation)
	state := core.ParserStateDraft
	if content.Validation.Valid {
		state = core.ParserStateValidated
	}
	item, err := scanParserContent(p.pool.QueryRow(ctx, parserUpdate+` SET validation=$4,state=$5,updated_at=now() WHERE tenant_id=$1 AND parser_id=$2 AND version=$3 RETURNING `+parserColumns, content.TenantID, content.ParserID, content.Version, validation, state))
	if errors.Is(err, pgx.ErrNoRows) {
		return core.ParserContent{}, ErrNotFound
	}
	return item, err
}

func (p *Postgres) PublishParserContent(ctx context.Context, tenantID, parserID string, version int) (core.ParserContent, error) {
	tx, err := p.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return core.ParserContent{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	content, err := scanParserContent(tx.QueryRow(ctx, parserSelect+` WHERE tenant_id=$1 AND parser_id=$2 AND version=$3 FOR UPDATE`, tenantID, parserID, version))
	if errors.Is(err, pgx.ErrNoRows) {
		return core.ParserContent{}, ErrNotFound
	}
	if err != nil {
		return core.ParserContent{}, err
	}
	if !content.Validation.Valid {
		return core.ParserContent{}, ErrParserStateConflict
	}
	if _, err = tx.Exec(ctx, `UPDATE parser_versions SET state=$3,updated_at=now() WHERE tenant_id=$1 AND state=$4 AND spec->>'format'=$2`, tenantID, content.Spec.Format, core.ParserStateSuperseded, core.ParserStatePublished); err != nil {
		return core.ParserContent{}, err
	}
	published, err := scanParserContent(tx.QueryRow(ctx, parserUpdate+` SET state=$4,published_at=now(),updated_at=now() WHERE tenant_id=$1 AND parser_id=$2 AND version=$3 RETURNING `+parserColumns, tenantID, parserID, version, core.ParserStatePublished))
	if err != nil {
		return core.ParserContent{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return core.ParserContent{}, err
	}
	return published, nil
}

func (p *Postgres) DisableParserContent(ctx context.Context, tenantID, parserID string) (core.ParserContent, error) {
	item, err := scanParserContent(p.pool.QueryRow(ctx, parserUpdate+` SET state=$3,updated_at=now() WHERE tenant_id=$1 AND parser_id=$2 AND state=$4 RETURNING `+parserColumns, tenantID, parserID, core.ParserStateDisabled, core.ParserStatePublished))
	if errors.Is(err, pgx.ErrNoRows) {
		return core.ParserContent{}, ErrNotFound
	}
	return item, err
}

func (p *Postgres) PublishedParserByFormat(ctx context.Context, tenantID, format string) (core.ParserContent, bool, error) {
	item, err := scanParserContent(p.pool.QueryRow(ctx, parserSelect+` WHERE tenant_id=$1 AND state=$2 AND spec->>'format'=$3 ORDER BY version DESC LIMIT 1`, tenantID, core.ParserStatePublished, format))
	if errors.Is(err, pgx.ErrNoRows) {
		return core.ParserContent{}, false, nil
	}
	return item, err == nil, err
}

const parserColumns = `parser_id,tenant_id,version,name,state,spec,validation,created_by,request_id,created_at,updated_at,published_at`
const parserSelect = `SELECT ` + parserColumns + ` FROM parser_versions`
const parserSelectInsert = `INSERT INTO parser_versions (tenant_id,parser_id,version,name,state,spec,validation,created_by,request_id,created_at,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING ` + parserColumns
const parserUpdate = `UPDATE parser_versions`

func scanParserContent(row parserRow) (core.ParserContent, error) {
	var item core.ParserContent
	var spec, validation []byte
	err := row.Scan(&item.ParserID, &item.TenantID, &item.Version, &item.Name, &item.State, &spec, &validation, &item.CreatedBy, &item.RequestID, &item.CreatedAt, &item.UpdatedAt, &item.PublishedAt)
	if err != nil {
		return core.ParserContent{}, err
	}
	if err = json.Unmarshal(spec, &item.Spec); err != nil {
		return core.ParserContent{}, err
	}
	if err = json.Unmarshal(validation, &item.Validation); err != nil {
		return core.ParserContent{}, err
	}
	return item, nil
}
