package store

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/kcsp/platform/internal/core"
)

type ServiceAccountStore interface {
	CreateServiceAccount(context.Context, core.ServiceAccount, []byte) (core.ServiceAccount, error)
	ListServiceAccounts(context.Context, string) ([]core.ServiceAccount, error)
	RotateServiceAccountToken(context.Context, string, string, string, []byte, time.Time) (core.ServiceAccount, error)
	RevokeServiceAccount(context.Context, string, string, string) (core.ServiceAccount, error)
	ServiceAccountByTokenHash(context.Context, []byte) (core.ServiceAccount, error)
}

type memoryServiceAccountReference struct {
	tenantID  string
	accountID string
}

const serviceAccountColumns = `tenant_id,service_account_id,name,description,scopes,token_version,created_by,created_at,updated_at,expires_at,last_used_at,revoked_at`

func (p *Postgres) CreateServiceAccount(ctx context.Context, account core.ServiceAccount, tokenHash []byte) (core.ServiceAccount, error) {
	if len(tokenHash) != 32 {
		return core.ServiceAccount{}, errors.New("service account token hash must be SHA-256")
	}
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return core.ServiceAccount{}, fmt.Errorf("begin service account creation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	created, err := scanServiceAccount(tx.QueryRow(ctx, `INSERT INTO service_accounts
		(tenant_id,service_account_id,name,description,scopes,token_hash,token_version,created_by,created_at,updated_at,expires_at)
		VALUES($1,$2,$3,$4,$5,$6,1,$7,$8,$8,$9) RETURNING `+serviceAccountColumns,
		account.TenantID, account.ID, account.Name, account.Description, account.Scopes, tokenHash, account.CreatedBy, account.CreatedAt, account.ExpiresAt))
	if err != nil {
		var postgresError *pgconn.PgError
		if errors.As(err, &postgresError) && postgresError.Code == "23505" {
			return core.ServiceAccount{}, ErrAlreadyExists
		}
		return core.ServiceAccount{}, fmt.Errorf("create service account: %w", err)
	}
	if _, err := appendAuditTx(ctx, tx, serviceAccountAudit(created, created.CreatedBy, "service_account.created")); err != nil {
		return core.ServiceAccount{}, fmt.Errorf("audit service account creation: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return core.ServiceAccount{}, fmt.Errorf("commit service account creation: %w", err)
	}
	return created, nil
}

func (p *Postgres) ListServiceAccounts(ctx context.Context, tenantID string) ([]core.ServiceAccount, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+serviceAccountColumns+` FROM service_accounts WHERE tenant_id=$1 ORDER BY created_at DESC,service_account_id`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list service accounts: %w", err)
	}
	defer rows.Close()
	items := []core.ServiceAccount{}
	for rows.Next() {
		item, err := scanServiceAccount(rows)
		if err != nil {
			return nil, fmt.Errorf("scan service account: %w", err)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (p *Postgres) RotateServiceAccountToken(ctx context.Context, tenantID, accountID, actor string, tokenHash []byte, expiresAt time.Time) (core.ServiceAccount, error) {
	if len(tokenHash) != 32 {
		return core.ServiceAccount{}, errors.New("service account token hash must be SHA-256")
	}
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return core.ServiceAccount{}, fmt.Errorf("begin service account rotation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	account, err := scanServiceAccount(tx.QueryRow(ctx, `UPDATE service_accounts SET token_hash=$3,token_version=token_version+1,
		expires_at=$4,updated_at=now(),last_used_at=NULL WHERE tenant_id=$1 AND service_account_id=$2 AND revoked_at IS NULL
		RETURNING `+serviceAccountColumns, tenantID, accountID, tokenHash, expiresAt))
	if errors.Is(err, pgx.ErrNoRows) {
		return core.ServiceAccount{}, ErrNotFound
	}
	if err != nil {
		return core.ServiceAccount{}, fmt.Errorf("rotate service account token: %w", err)
	}
	if _, err := appendAuditTx(ctx, tx, serviceAccountAudit(account, actor, "service_account.token_rotated")); err != nil {
		return core.ServiceAccount{}, fmt.Errorf("audit service account rotation: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return core.ServiceAccount{}, fmt.Errorf("commit service account rotation: %w", err)
	}
	return account, nil
}

func (p *Postgres) RevokeServiceAccount(ctx context.Context, tenantID, accountID, actor string) (core.ServiceAccount, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return core.ServiceAccount{}, fmt.Errorf("begin service account revocation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	account, err := scanServiceAccount(tx.QueryRow(ctx, `UPDATE service_accounts SET revoked_at=now(),updated_at=now()
		WHERE tenant_id=$1 AND service_account_id=$2 AND revoked_at IS NULL RETURNING `+serviceAccountColumns, tenantID, accountID))
	if errors.Is(err, pgx.ErrNoRows) {
		return core.ServiceAccount{}, ErrNotFound
	}
	if err != nil {
		return core.ServiceAccount{}, fmt.Errorf("revoke service account: %w", err)
	}
	if _, err := appendAuditTx(ctx, tx, serviceAccountAudit(account, actor, "service_account.revoked")); err != nil {
		return core.ServiceAccount{}, fmt.Errorf("audit service account revocation: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return core.ServiceAccount{}, fmt.Errorf("commit service account revocation: %w", err)
	}
	return account, nil
}

func (p *Postgres) ServiceAccountByTokenHash(ctx context.Context, tokenHash []byte) (core.ServiceAccount, error) {
	if len(tokenHash) != 32 {
		return core.ServiceAccount{}, ErrNotFound
	}
	account, err := scanServiceAccount(p.pool.QueryRow(ctx, `UPDATE service_accounts SET last_used_at=now()
		WHERE token_hash=$1 AND revoked_at IS NULL AND expires_at>now() RETURNING `+serviceAccountColumns, tokenHash))
	if errors.Is(err, pgx.ErrNoRows) {
		return core.ServiceAccount{}, ErrNotFound
	}
	if err != nil {
		return core.ServiceAccount{}, fmt.Errorf("authenticate service account: %w", err)
	}
	return account, nil
}

func (m *MemoryRepository) CreateServiceAccount(ctx context.Context, account core.ServiceAccount, tokenHash []byte) (core.ServiceAccount, error) {
	if err := ctx.Err(); err != nil {
		return core.ServiceAccount{}, err
	}
	if len(tokenHash) != 32 {
		return core.ServiceAccount{}, errors.New("service account token hash must be SHA-256")
	}
	m.serviceAccountMu.Lock()
	if m.serviceAccounts[account.TenantID] == nil {
		m.serviceAccounts[account.TenantID] = map[string]core.ServiceAccount{}
	}
	for _, existing := range m.serviceAccounts[account.TenantID] {
		if strings.EqualFold(existing.Name, account.Name) {
			m.serviceAccountMu.Unlock()
			return core.ServiceAccount{}, ErrAlreadyExists
		}
	}
	account.Scopes = append([]string(nil), account.Scopes...)
	account.TokenVersion = 1
	account.State = core.ServiceAccountStateActive
	m.serviceAccounts[account.TenantID][account.ID] = account
	m.serviceAccountTokens[hex.EncodeToString(tokenHash)] = memoryServiceAccountReference{tenantID: account.TenantID, accountID: account.ID}
	m.serviceAccountMu.Unlock()
	m.memory.AppendAudit(serviceAccountAudit(account, account.CreatedBy, "service_account.created"))
	return account, nil
}

func (m *MemoryRepository) ListServiceAccounts(ctx context.Context, tenantID string) ([]core.ServiceAccount, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.serviceAccountMu.RLock()
	defer m.serviceAccountMu.RUnlock()
	items := make([]core.ServiceAccount, 0, len(m.serviceAccounts[tenantID]))
	for _, account := range m.serviceAccounts[tenantID] {
		items = append(items, cloneServiceAccount(account))
	}
	sort.Slice(items, func(i, j int) bool { return items[i].CreatedAt.After(items[j].CreatedAt) })
	return items, nil
}

func (m *MemoryRepository) RotateServiceAccountToken(ctx context.Context, tenantID, accountID, actor string, tokenHash []byte, expiresAt time.Time) (core.ServiceAccount, error) {
	if err := ctx.Err(); err != nil {
		return core.ServiceAccount{}, err
	}
	if len(tokenHash) != 32 {
		return core.ServiceAccount{}, errors.New("service account token hash must be SHA-256")
	}
	m.serviceAccountMu.Lock()
	account, found := m.serviceAccounts[tenantID][accountID]
	if !found || account.RevokedAt != nil {
		m.serviceAccountMu.Unlock()
		return core.ServiceAccount{}, ErrNotFound
	}
	for hash, reference := range m.serviceAccountTokens {
		if reference.tenantID == tenantID && reference.accountID == accountID {
			delete(m.serviceAccountTokens, hash)
		}
	}
	now := time.Now().UTC()
	account.TokenVersion++
	account.ExpiresAt = expiresAt
	account.UpdatedAt = now
	account.LastUsedAt = nil
	account.State = core.ServiceAccountStateActive
	m.serviceAccounts[tenantID][accountID] = account
	m.serviceAccountTokens[hex.EncodeToString(tokenHash)] = memoryServiceAccountReference{tenantID: tenantID, accountID: accountID}
	m.serviceAccountMu.Unlock()
	m.memory.AppendAudit(serviceAccountAudit(account, actor, "service_account.token_rotated"))
	return cloneServiceAccount(account), nil
}

func (m *MemoryRepository) RevokeServiceAccount(ctx context.Context, tenantID, accountID, actor string) (core.ServiceAccount, error) {
	if err := ctx.Err(); err != nil {
		return core.ServiceAccount{}, err
	}
	m.serviceAccountMu.Lock()
	account, found := m.serviceAccounts[tenantID][accountID]
	if !found || account.RevokedAt != nil {
		m.serviceAccountMu.Unlock()
		return core.ServiceAccount{}, ErrNotFound
	}
	now := time.Now().UTC()
	account.RevokedAt = &now
	account.UpdatedAt = now
	account.State = core.ServiceAccountStateRevoked
	m.serviceAccounts[tenantID][accountID] = account
	for hash, reference := range m.serviceAccountTokens {
		if reference.tenantID == tenantID && reference.accountID == accountID {
			delete(m.serviceAccountTokens, hash)
		}
	}
	m.serviceAccountMu.Unlock()
	m.memory.AppendAudit(serviceAccountAudit(account, actor, "service_account.revoked"))
	return cloneServiceAccount(account), nil
}

func (m *MemoryRepository) ServiceAccountByTokenHash(ctx context.Context, tokenHash []byte) (core.ServiceAccount, error) {
	if err := ctx.Err(); err != nil {
		return core.ServiceAccount{}, err
	}
	if len(tokenHash) != 32 {
		return core.ServiceAccount{}, ErrNotFound
	}
	m.serviceAccountMu.Lock()
	defer m.serviceAccountMu.Unlock()
	reference, found := m.serviceAccountTokens[hex.EncodeToString(tokenHash)]
	if !found {
		return core.ServiceAccount{}, ErrNotFound
	}
	account, found := m.serviceAccounts[reference.tenantID][reference.accountID]
	if !found || account.RevokedAt != nil || !account.ExpiresAt.After(time.Now().UTC()) {
		return core.ServiceAccount{}, ErrNotFound
	}
	now := time.Now().UTC()
	account.LastUsedAt = &now
	m.serviceAccounts[reference.tenantID][reference.accountID] = account
	return cloneServiceAccount(account), nil
}

func (m *MemoryRepository) resetServiceAccounts(tenantID string) {
	m.serviceAccountMu.Lock()
	defer m.serviceAccountMu.Unlock()
	delete(m.serviceAccounts, tenantID)
	for hash, reference := range m.serviceAccountTokens {
		if reference.tenantID == tenantID {
			delete(m.serviceAccountTokens, hash)
		}
	}
}

func (h *Hybrid) CreateServiceAccount(ctx context.Context, account core.ServiceAccount, tokenHash []byte) (core.ServiceAccount, error) {
	return h.control.CreateServiceAccount(ctx, account, tokenHash)
}
func (h *Hybrid) ListServiceAccounts(ctx context.Context, tenantID string) ([]core.ServiceAccount, error) {
	return h.control.ListServiceAccounts(ctx, tenantID)
}
func (h *Hybrid) RotateServiceAccountToken(ctx context.Context, tenantID, accountID, actor string, tokenHash []byte, expiresAt time.Time) (core.ServiceAccount, error) {
	return h.control.RotateServiceAccountToken(ctx, tenantID, accountID, actor, tokenHash, expiresAt)
}
func (h *Hybrid) RevokeServiceAccount(ctx context.Context, tenantID, accountID, actor string) (core.ServiceAccount, error) {
	return h.control.RevokeServiceAccount(ctx, tenantID, accountID, actor)
}
func (h *Hybrid) ServiceAccountByTokenHash(ctx context.Context, tokenHash []byte) (core.ServiceAccount, error) {
	return h.control.ServiceAccountByTokenHash(ctx, tokenHash)
}

type serviceAccountScanner interface {
	Scan(...interface{}) error
}

func scanServiceAccount(scanner serviceAccountScanner) (core.ServiceAccount, error) {
	var account core.ServiceAccount
	if err := scanner.Scan(&account.TenantID, &account.ID, &account.Name, &account.Description, &account.Scopes,
		&account.TokenVersion, &account.CreatedBy, &account.CreatedAt, &account.UpdatedAt, &account.ExpiresAt,
		&account.LastUsedAt, &account.RevokedAt); err != nil {
		return core.ServiceAccount{}, err
	}
	account.State = core.ServiceAccountStateActive
	if account.RevokedAt != nil {
		account.State = core.ServiceAccountStateRevoked
	} else if !account.ExpiresAt.After(time.Now().UTC()) {
		account.State = core.ServiceAccountStateExpired
	}
	return account, nil
}

func cloneServiceAccount(account core.ServiceAccount) core.ServiceAccount {
	account.Scopes = append([]string(nil), account.Scopes...)
	return account
}

func serviceAccountAudit(account core.ServiceAccount, actor, action string) core.AuditEntry {
	return core.AuditEntry{
		TenantID: account.TenantID, Actor: actor, Action: action, ResourceType: "service_account", ResourceID: account.ID, Outcome: "success",
		Metadata: map[string]interface{}{"name": account.Name, "scopes": account.Scopes, "token_version": account.TokenVersion, "expires_at": account.ExpiresAt},
	}
}
