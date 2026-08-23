package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/kcsp/platform/internal/core"
)

type licenseRow interface{ Scan(...any) error }

func (p *Postgres) GetTenant(ctx context.Context, tenantID string) (core.Tenant, error) {
	var item core.Tenant
	err := p.pool.QueryRow(ctx, `SELECT tenant_id,display_name,state,created_at,updated_at FROM tenants WHERE tenant_id=$1`, tenantID).Scan(&item.ID, &item.DisplayName, &item.State, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return core.Tenant{}, ErrNotFound
	}
	return item, err
}

func (p *Postgres) ListTenants(ctx context.Context) ([]core.Tenant, error) {
	rows, err := p.pool.Query(ctx, `SELECT tenant_id,display_name,state,created_at,updated_at FROM tenants ORDER BY display_name,tenant_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []core.Tenant{}
	for rows.Next() {
		var item core.Tenant
		if err = rows.Scan(&item.ID, &item.DisplayName, &item.State, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (p *Postgres) CreateTenant(ctx context.Context, item core.Tenant) (core.Tenant, error) {
	tx, err := p.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return core.Tenant{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	created := core.Tenant{}
	err = tx.QueryRow(ctx, `INSERT INTO tenants(tenant_id,display_name,state,created_at,updated_at) VALUES($1,$2,$3,$4,$5) RETURNING tenant_id,display_name,state,created_at,updated_at`, item.ID, item.DisplayName, item.State, item.CreatedAt, item.UpdatedAt).Scan(&created.ID, &created.DisplayName, &created.State, &created.CreatedAt, &created.UpdatedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return core.Tenant{}, ErrAlreadyExists
		}
		return core.Tenant{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO audit_heads(tenant_id) VALUES($1) ON CONFLICT DO NOTHING`, item.ID); err != nil {
		return core.Tenant{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return core.Tenant{}, err
	}
	return created, nil
}

func (p *Postgres) SetTenantState(ctx context.Context, tenantID, state string) (core.Tenant, error) {
	var item core.Tenant
	err := p.pool.QueryRow(ctx, `UPDATE tenants SET state=$2,updated_at=now() WHERE tenant_id=$1 RETURNING tenant_id,display_name,state,created_at,updated_at`, tenantID, state).Scan(&item.ID, &item.DisplayName, &item.State, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return core.Tenant{}, ErrNotFound
	}
	return item, err
}

func (p *Postgres) InstallLicense(ctx context.Context, record core.LicenseRecord) (core.LicenseRecord, bool, error) {
	tx, err := p.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return core.LicenseRecord{}, false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, record.TenantID+"|license"); err != nil {
		return core.LicenseRecord{}, false, err
	}
	if record.RequestID != "" {
		existing, findErr := scanLicense(tx.QueryRow(ctx, licenseSelect+` WHERE tenant_id=$1 AND request_id=$2`, record.TenantID, record.RequestID))
		if findErr == nil {
			return existing, false, tx.Commit(ctx)
		}
		if !errors.Is(findErr, pgx.ErrNoRows) {
			return core.LicenseRecord{}, false, findErr
		}
	}
	existing, findErr := scanLicense(tx.QueryRow(ctx, licenseSelect+` WHERE tenant_id=$1 AND license_id=$2`, record.TenantID, record.LicenseID))
	if findErr == nil {
		if existing.Fingerprint != record.Fingerprint {
			return core.LicenseRecord{}, false, ErrAlreadyExists
		}
		if _, err = tx.Exec(ctx, `UPDATE tenant_licenses SET active=(license_id=$2) WHERE tenant_id=$1`, record.TenantID, record.LicenseID); err != nil {
			return core.LicenseRecord{}, false, err
		}
		existing.Active = true
		return existing, false, tx.Commit(ctx)
	}
	if !errors.Is(findErr, pgx.ErrNoRows) {
		return core.LicenseRecord{}, false, findErr
	}
	payload, err := json.Marshal(record.Payload)
	if err != nil {
		return core.LicenseRecord{}, false, err
	}
	envelope, err := json.Marshal(record.Envelope)
	if err != nil {
		return core.LicenseRecord{}, false, err
	}
	if _, err = tx.Exec(ctx, `UPDATE tenant_licenses SET active=FALSE WHERE tenant_id=$1 AND active`, record.TenantID); err != nil {
		return core.LicenseRecord{}, false, err
	}
	created, err := scanLicense(tx.QueryRow(ctx, licenseInsert, record.TenantID, record.LicenseID, record.KeyID, payload, envelope, record.Fingerprint, record.InstalledBy, record.RequestID, record.InstalledAt))
	if err != nil {
		return core.LicenseRecord{}, false, fmt.Errorf("install license: %w", err)
	}
	if err = tx.Commit(ctx); err != nil {
		return core.LicenseRecord{}, false, err
	}
	return created, true, nil
}

func (p *Postgres) CurrentLicense(ctx context.Context, tenantID string) (core.LicenseRecord, bool, error) {
	record, err := scanLicense(p.pool.QueryRow(ctx, licenseSelect+` WHERE tenant_id=$1 AND active ORDER BY installed_at DESC LIMIT 1`, tenantID))
	if errors.Is(err, pgx.ErrNoRows) {
		return core.LicenseRecord{}, false, nil
	}
	return record, err == nil, err
}

func (p *Postgres) ListLicenses(ctx context.Context, tenantID string) ([]core.LicenseRecord, error) {
	rows, err := p.pool.Query(ctx, licenseSelect+` WHERE tenant_id=$1 ORDER BY installed_at DESC,license_id`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []core.LicenseRecord{}
	for rows.Next() {
		item, scanErr := scanLicense(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

const licenseColumns = `tenant_id,license_id,key_id,payload,envelope,fingerprint_sha256,installed_by,request_id,active,installed_at`
const licenseSelect = `SELECT ` + licenseColumns + ` FROM tenant_licenses`
const licenseInsert = `INSERT INTO tenant_licenses(tenant_id,license_id,key_id,payload,envelope,fingerprint_sha256,installed_by,request_id,active,installed_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,TRUE,$9) RETURNING ` + licenseColumns

func scanLicense(row licenseRow) (core.LicenseRecord, error) {
	var item core.LicenseRecord
	var payload, envelope []byte
	err := row.Scan(&item.TenantID, &item.LicenseID, &item.KeyID, &payload, &envelope, &item.Fingerprint, &item.InstalledBy, &item.RequestID, &item.Active, &item.InstalledAt)
	if err != nil {
		return core.LicenseRecord{}, err
	}
	if err = json.Unmarshal(payload, &item.Payload); err != nil {
		return core.LicenseRecord{}, err
	}
	if err = json.Unmarshal(envelope, &item.Envelope); err != nil {
		return core.LicenseRecord{}, err
	}
	return item, nil
}

func normalizeTenantState(value string) string {
	return strings.ToUpper(strings.TrimSpace(value))
}
