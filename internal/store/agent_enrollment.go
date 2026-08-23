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

var ErrEnrollmentRejected = errors.New("agent enrollment token rejected")

type AgentEnrollmentStore interface {
	CreateAgentEnrollmentToken(context.Context, core.AgentEnrollmentToken, []byte) (core.AgentEnrollmentToken, error)
	ListAgentEnrollmentTokens(context.Context, string) ([]core.AgentEnrollmentToken, error)
	RevokeAgentEnrollmentToken(context.Context, string, string, string) (core.AgentEnrollmentToken, error)
	ConsumeAgentEnrollment(context.Context, []byte, core.Collector, core.AgentCredential, []byte) (core.Collector, error)
	AgentCredentialByHash(context.Context, []byte) (core.AgentCredential, error)
	RotateAgentCredential(context.Context, []byte, core.AgentCredential, []byte) (core.AgentCredential, error)
}

const agentEnrollmentTokenColumns = `tenant_id,token_id,label,collector_type,capabilities,state,expires_at,max_uses,use_count,created_by,created_at,last_used_at`
const agentCredentialColumns = `credential_id,tenant_id,collector_id,auth_subject,expires_at,created_at,last_used_at,revoked_at`

func (p *Postgres) CreateAgentEnrollmentToken(ctx context.Context, token core.AgentEnrollmentToken, tokenHash []byte) (core.AgentEnrollmentToken, error) {
	if len(tokenHash) != 32 {
		return core.AgentEnrollmentToken{}, errors.New("agent enrollment token hash must be SHA-256")
	}
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return core.AgentEnrollmentToken{}, fmt.Errorf("begin agent enrollment token creation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	created, err := scanAgentEnrollmentToken(tx.QueryRow(ctx, `INSERT INTO agent_enrollment_tokens
		(tenant_id,token_id,label,token_hash,collector_type,capabilities,state,expires_at,max_uses,use_count,created_by,created_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,0,$10,$11)
		RETURNING `+agentEnrollmentTokenColumns,
		token.TenantID, token.ID, token.Label, tokenHash, token.CollectorType, token.Capabilities,
		core.AgentEnrollmentStateActive, token.ExpiresAt, token.MaxUses, token.CreatedBy, token.CreatedAt))
	if err != nil {
		var postgresError *pgconn.PgError
		if errors.As(err, &postgresError) && postgresError.Code == "23505" {
			return core.AgentEnrollmentToken{}, ErrAlreadyExists
		}
		return core.AgentEnrollmentToken{}, fmt.Errorf("create agent enrollment token: %w", err)
	}
	if _, err := appendAuditTx(ctx, tx, core.AuditEntry{
		TenantID: created.TenantID, Actor: created.CreatedBy, Action: "agent.enrollment_token.created",
		ResourceType: "agent_enrollment_token", ResourceID: created.ID, Outcome: "success",
		Metadata: map[string]interface{}{
			"label": created.Label, "collector_type": created.CollectorType, "capabilities": created.Capabilities,
			"expires_at": created.ExpiresAt, "max_uses": created.MaxUses,
		},
	}); err != nil {
		return core.AgentEnrollmentToken{}, fmt.Errorf("audit agent enrollment token creation: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return core.AgentEnrollmentToken{}, fmt.Errorf("commit agent enrollment token creation: %w", err)
	}
	return created, nil
}

func (p *Postgres) ListAgentEnrollmentTokens(ctx context.Context, tenantID string) ([]core.AgentEnrollmentToken, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+agentEnrollmentTokenColumns+` FROM agent_enrollment_tokens
		WHERE tenant_id=$1 ORDER BY created_at DESC,token_id`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list agent enrollment tokens: %w", err)
	}
	defer rows.Close()
	items := []core.AgentEnrollmentToken{}
	for rows.Next() {
		item, err := scanAgentEnrollmentToken(rows)
		if err != nil {
			return nil, fmt.Errorf("scan agent enrollment token: %w", err)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (p *Postgres) RevokeAgentEnrollmentToken(ctx context.Context, tenantID, tokenID, actor string) (core.AgentEnrollmentToken, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return core.AgentEnrollmentToken{}, fmt.Errorf("begin agent enrollment token revocation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	item, err := scanAgentEnrollmentToken(tx.QueryRow(ctx, `UPDATE agent_enrollment_tokens SET state=$3
		WHERE tenant_id=$1 AND token_id=$2 RETURNING `+agentEnrollmentTokenColumns,
		tenantID, tokenID, core.AgentEnrollmentStateRevoked))
	if errors.Is(err, pgx.ErrNoRows) {
		return core.AgentEnrollmentToken{}, ErrNotFound
	}
	if err != nil {
		return core.AgentEnrollmentToken{}, fmt.Errorf("revoke agent enrollment token: %w", err)
	}
	if _, err := appendAuditTx(ctx, tx, core.AuditEntry{
		TenantID: item.TenantID, Actor: actor, Action: "agent.enrollment_token.revoked",
		ResourceType: "agent_enrollment_token", ResourceID: item.ID, Outcome: "success",
		Metadata: map[string]interface{}{
			"label": item.Label, "collector_type": item.CollectorType, "use_count": item.UseCount, "max_uses": item.MaxUses,
		},
	}); err != nil {
		return core.AgentEnrollmentToken{}, fmt.Errorf("audit agent enrollment token revocation: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return core.AgentEnrollmentToken{}, fmt.Errorf("commit agent enrollment token revocation: %w", err)
	}
	return item, nil
}

func (p *Postgres) ConsumeAgentEnrollment(ctx context.Context, tokenHash []byte, collector core.Collector, credential core.AgentCredential, credentialHash []byte) (core.Collector, error) {
	if len(tokenHash) != 32 || len(credentialHash) != 32 {
		return core.Collector{}, ErrEnrollmentRejected
	}
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return core.Collector{}, fmt.Errorf("begin agent enrollment: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	token, err := scanAgentEnrollmentToken(tx.QueryRow(ctx, `SELECT `+agentEnrollmentTokenColumns+`
		FROM agent_enrollment_tokens WHERE token_hash=$1 FOR UPDATE`, tokenHash))
	if errors.Is(err, pgx.ErrNoRows) {
		return core.Collector{}, ErrEnrollmentRejected
	}
	if err != nil {
		return core.Collector{}, fmt.Errorf("lock agent enrollment token: %w", err)
	}
	now := time.Now().UTC()
	if token.State != core.AgentEnrollmentStateActive || !token.ExpiresAt.After(now) || token.UseCount >= token.MaxUses {
		return core.Collector{}, ErrEnrollmentRejected
	}
	collector.TenantID = token.TenantID
	collector.Type = token.CollectorType
	collector.Capabilities = append([]string(nil), token.Capabilities...)
	collector.State = "ACTIVE"
	if collector.HealthMetadata == nil {
		collector.HealthMetadata = map[string]interface{}{}
	}
	metadata, err := json.Marshal(collector.HealthMetadata)
	if err != nil {
		return core.Collector{}, fmt.Errorf("encode enrolled collector metadata: %w", err)
	}
	created, err := scanCollector(tx.QueryRow(ctx, `INSERT INTO collectors
		(tenant_id,collector_id,name,collector_type,auth_subject,state,capabilities,version,observed_ip,health_metadata,last_seen_at,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NULL,$11,$11)
		RETURNING tenant_id,collector_id,name,collector_type,auth_subject,state,capabilities,version,observed_ip,
		health_metadata,last_seen_at,created_at,updated_at`, collector.TenantID, collector.ID, collector.Name, collector.Type,
		collector.AuthSubject, collector.State, collector.Capabilities, collector.Version, collector.ObservedIP, metadata, now))
	if err != nil {
		var postgresError *pgconn.PgError
		if errors.As(err, &postgresError) && postgresError.Code == "23505" {
			return core.Collector{}, ErrAlreadyExists
		}
		return core.Collector{}, fmt.Errorf("register enrolled collector: %w", err)
	}
	credential.TenantID = created.TenantID
	credential.CollectorID = created.ID
	credential.AuthSubject = created.AuthSubject
	credential.CreatedAt = now
	if !credential.ExpiresAt.After(now) {
		return core.Collector{}, errors.New("agent credential expiry must be in the future")
	}
	if _, err := tx.Exec(ctx, `INSERT INTO agent_credentials
		(credential_id,tenant_id,collector_id,auth_subject,token_hash,expires_at,created_at)
		VALUES($1,$2,$3,$4,$5,$6,$7)`, credential.ID, credential.TenantID, credential.CollectorID,
		credential.AuthSubject, credentialHash, credential.ExpiresAt, credential.CreatedAt); err != nil {
		return core.Collector{}, fmt.Errorf("create agent credential: %w", err)
	}
	useCount := token.UseCount + 1
	state := core.AgentEnrollmentStateActive
	if useCount >= token.MaxUses {
		state = core.AgentEnrollmentStateExhausted
	}
	if _, err := tx.Exec(ctx, `UPDATE agent_enrollment_tokens SET use_count=$3,state=$4,last_used_at=$5
		WHERE tenant_id=$1 AND token_id=$2`, token.TenantID, token.ID, useCount, state, now); err != nil {
		return core.Collector{}, fmt.Errorf("consume agent enrollment token: %w", err)
	}
	if _, err := appendAuditTx(ctx, tx, core.AuditEntry{
		TenantID: created.TenantID, Actor: created.AuthSubject, Action: "agent.enrolled",
		ResourceType: "collector", ResourceID: created.ID, Outcome: "success", CreatedAt: now,
		Metadata: map[string]interface{}{
			"enrollment_token_id": token.ID, "credential_id": credential.ID, "collector_type": created.Type,
			"version": created.Version, "observed_ip": created.ObservedIP,
		},
	}); err != nil {
		return core.Collector{}, fmt.Errorf("audit agent enrollment: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return core.Collector{}, fmt.Errorf("commit agent enrollment: %w", err)
	}
	return created, nil
}

func (p *Postgres) AgentCredentialByHash(ctx context.Context, tokenHash []byte) (core.AgentCredential, error) {
	if len(tokenHash) != 32 {
		return core.AgentCredential{}, ErrNotFound
	}
	credential, err := scanAgentCredential(p.pool.QueryRow(ctx, `SELECT `+prefixedAgentCredentialColumns("ac")+`
		FROM agent_credentials ac JOIN collectors c ON c.tenant_id=ac.tenant_id AND c.collector_id=ac.collector_id
		WHERE ac.token_hash=$1 AND ac.revoked_at IS NULL AND ac.expires_at>now() AND c.state='ACTIVE'`, tokenHash))
	if errors.Is(err, pgx.ErrNoRows) {
		return core.AgentCredential{}, ErrNotFound
	}
	if err != nil {
		return core.AgentCredential{}, fmt.Errorf("authenticate agent credential: %w", err)
	}
	return credential, nil
}

func (p *Postgres) RotateAgentCredential(ctx context.Context, oldHash []byte, replacement core.AgentCredential, replacementHash []byte) (core.AgentCredential, error) {
	if len(oldHash) != 32 || len(replacementHash) != 32 {
		return core.AgentCredential{}, ErrNotFound
	}
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return core.AgentCredential{}, fmt.Errorf("begin agent credential rotation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	current, err := scanAgentCredential(tx.QueryRow(ctx, `SELECT `+agentCredentialColumns+` FROM agent_credentials
		WHERE token_hash=$1 FOR UPDATE`, oldHash))
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && (current.RevokedAt != nil || !current.ExpiresAt.After(time.Now().UTC()))) {
		return core.AgentCredential{}, ErrNotFound
	}
	if err != nil {
		return core.AgentCredential{}, fmt.Errorf("lock agent credential: %w", err)
	}
	var state string
	if err := tx.QueryRow(ctx, `SELECT state FROM collectors WHERE tenant_id=$1 AND collector_id=$2`, current.TenantID, current.CollectorID).Scan(&state); errors.Is(err, pgx.ErrNoRows) {
		return core.AgentCredential{}, ErrNotFound
	} else if err != nil {
		return core.AgentCredential{}, fmt.Errorf("check collector during credential rotation: %w", err)
	}
	if state != "ACTIVE" {
		return core.AgentCredential{}, ErrNotFound
	}
	now := time.Now().UTC()
	replacement.TenantID = current.TenantID
	replacement.CollectorID = current.CollectorID
	replacement.AuthSubject = current.AuthSubject
	replacement.CreatedAt = now
	if !replacement.ExpiresAt.After(now) {
		return core.AgentCredential{}, errors.New("replacement agent credential expiry must be in the future")
	}
	if _, err := tx.Exec(ctx, `INSERT INTO agent_credentials
		(credential_id,tenant_id,collector_id,auth_subject,token_hash,expires_at,created_at)
		VALUES($1,$2,$3,$4,$5,$6,$7)`, replacement.ID, replacement.TenantID, replacement.CollectorID,
		replacement.AuthSubject, replacementHash, replacement.ExpiresAt, replacement.CreatedAt); err != nil {
		return core.AgentCredential{}, fmt.Errorf("insert replacement agent credential: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE agent_credentials SET revoked_at=$2 WHERE credential_id=$1`, current.ID, now); err != nil {
		return core.AgentCredential{}, fmt.Errorf("revoke replaced agent credential: %w", err)
	}
	if _, err := appendAuditTx(ctx, tx, core.AuditEntry{
		TenantID: current.TenantID, Actor: current.AuthSubject, Action: "agent.credential.rotated",
		ResourceType: "agent_credential", ResourceID: replacement.ID, Outcome: "success", CreatedAt: now,
		Metadata: map[string]interface{}{
			"collector_id": current.CollectorID, "replaced_credential_id": current.ID,
			"replacement_credential_id": replacement.ID, "expires_at": replacement.ExpiresAt,
		},
	}); err != nil {
		return core.AgentCredential{}, fmt.Errorf("audit agent credential rotation: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return core.AgentCredential{}, fmt.Errorf("commit agent credential rotation: %w", err)
	}
	return replacement, nil
}

type agentEnrollmentScanner interface {
	Scan(...interface{}) error
}

func scanAgentEnrollmentToken(scanner agentEnrollmentScanner) (core.AgentEnrollmentToken, error) {
	var token core.AgentEnrollmentToken
	if err := scanner.Scan(&token.TenantID, &token.ID, &token.Label, &token.CollectorType, &token.Capabilities,
		&token.State, &token.ExpiresAt, &token.MaxUses, &token.UseCount, &token.CreatedBy, &token.CreatedAt, &token.LastUsedAt); err != nil {
		return core.AgentEnrollmentToken{}, err
	}
	if token.State == core.AgentEnrollmentStateActive && !token.ExpiresAt.After(time.Now().UTC()) {
		token.State = core.AgentEnrollmentStateExpired
	}
	return token, nil
}

func scanAgentCredential(scanner agentEnrollmentScanner) (core.AgentCredential, error) {
	var credential core.AgentCredential
	if err := scanner.Scan(&credential.ID, &credential.TenantID, &credential.CollectorID, &credential.AuthSubject,
		&credential.ExpiresAt, &credential.CreatedAt, &credential.LastUsedAt, &credential.RevokedAt); err != nil {
		return core.AgentCredential{}, err
	}
	return credential, nil
}

func prefixedAgentCredentialColumns(prefix string) string {
	return prefix + ".credential_id," + prefix + ".tenant_id," + prefix + ".collector_id," + prefix + ".auth_subject," +
		prefix + ".expires_at," + prefix + ".created_at," + prefix + ".last_used_at," + prefix + ".revoked_at"
}
