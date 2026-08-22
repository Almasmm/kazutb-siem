package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/kcsp/platform/internal/core"
)

var ErrAISOCIdempotencyMismatch = errors.New("AI SOC idempotency key payload mismatch")

const aiPolicyColumns = `tenant_id,enabled,cloud_allowed,pii_redaction,maximum_context_items,
	local_model,cloud_model,version,updated_by,updated_at`

const aiRequestColumns = `tenant_id,request_id,idempotency_key,request_hash,function,question,
	context_refs,context_snapshot,context_digest,status,provider,model,recommendation,requested_by,
	prompt_injection_detected,redaction_count,failure_class,failure_detail,attempt,version,
	lease_owner,lease_expires_at,created_at,started_at,completed_at,updated_at`

const aiDecisionColumns = `tenant_id,decision_id,request_id,decision,reason,decided_by,created_at`

func (p *Postgres) GetAISOCPolicy(ctx context.Context, tenantID string) (core.AISOCPolicy, error) {
	_, err := p.pool.Exec(ctx, `INSERT INTO ai_soc_policies(tenant_id)
		SELECT tenant_id FROM tenants WHERE tenant_id=$1 ON CONFLICT DO NOTHING`, tenantID)
	if err != nil {
		return core.AISOCPolicy{}, fmt.Errorf("ensure AI SOC policy: %w", err)
	}
	policy, err := scanAISOCPolicy(p.pool.QueryRow(ctx, `SELECT `+aiPolicyColumns+` FROM ai_soc_policies WHERE tenant_id=$1`, tenantID))
	if errors.Is(err, pgx.ErrNoRows) {
		return core.AISOCPolicy{}, ErrNotFound
	}
	if err != nil {
		return core.AISOCPolicy{}, fmt.Errorf("get AI SOC policy: %w", err)
	}
	return policy, nil
}

func (p *Postgres) UpdateAISOCPolicy(ctx context.Context, policy core.AISOCPolicy, expectedVersion int) (core.AISOCPolicy, error) {
	updated, err := scanAISOCPolicy(p.pool.QueryRow(ctx, `UPDATE ai_soc_policies SET enabled=$3,cloud_allowed=$4,
		pii_redaction=$5,maximum_context_items=$6,local_model=$7,cloud_model=$8,version=version+1,
		updated_by=$9,updated_at=$10 WHERE tenant_id=$1 AND version=$2 RETURNING `+aiPolicyColumns,
		policy.TenantID, expectedVersion, policy.Enabled, policy.CloudAllowed, policy.PIIRedaction,
		policy.MaximumContextItems, policy.LocalModel, policy.CloudModel, policy.UpdatedBy, policy.UpdatedAt))
	if errors.Is(err, pgx.ErrNoRows) {
		return core.AISOCPolicy{}, ErrVersionConflict
	}
	if err != nil {
		return core.AISOCPolicy{}, fmt.Errorf("update AI SOC policy: %w", err)
	}
	return updated, nil
}

func (p *Postgres) CreateAISOCRequest(ctx context.Context, request core.AISOCRequest) (core.AISOCRequest, bool, error) {
	refs, _ := json.Marshal(request.ContextRefs)
	tag, err := p.pool.Exec(ctx, `INSERT INTO ai_soc_requests(
		tenant_id,request_id,idempotency_key,request_hash,function,question,context_refs,status,
		provider,model,requested_by,attempt,version,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
		ON CONFLICT(tenant_id,idempotency_key) DO NOTHING`,
		request.TenantID, request.ID, request.IdempotencyKey, request.RequestHash, request.Function,
		request.Question, refs, request.Status, request.Provider, request.Model, request.RequestedBy,
		request.Attempt, request.Version, request.CreatedAt, request.UpdatedAt)
	if err != nil {
		return core.AISOCRequest{}, false, fmt.Errorf("create AI SOC request: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return request, true, nil
	}
	existing, err := scanAISOCRequest(p.pool.QueryRow(ctx, `SELECT `+aiRequestColumns+`
		FROM ai_soc_requests WHERE tenant_id=$1 AND idempotency_key=$2`, request.TenantID, request.IdempotencyKey))
	if err != nil {
		return core.AISOCRequest{}, false, fmt.Errorf("load idempotent AI SOC request: %w", err)
	}
	if existing.RequestHash != request.RequestHash {
		return core.AISOCRequest{}, false, ErrAISOCIdempotencyMismatch
	}
	return existing, false, nil
}

func (p *Postgres) GetAISOCRequest(ctx context.Context, tenantID, requestID string) (core.AISOCRequestDetails, error) {
	request, err := scanAISOCRequest(p.pool.QueryRow(ctx, `SELECT `+aiRequestColumns+`
		FROM ai_soc_requests WHERE tenant_id=$1 AND request_id=$2`, tenantID, requestID))
	if errors.Is(err, pgx.ErrNoRows) {
		return core.AISOCRequestDetails{}, ErrNotFound
	}
	if err != nil {
		return core.AISOCRequestDetails{}, fmt.Errorf("get AI SOC request: %w", err)
	}
	details := core.AISOCRequestDetails{Request: request}
	decision, err := scanAISOCDecision(p.pool.QueryRow(ctx, `SELECT `+aiDecisionColumns+`
		FROM ai_soc_decisions WHERE tenant_id=$1 AND request_id=$2`, tenantID, requestID))
	if err == nil {
		details.Decision = &decision
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return core.AISOCRequestDetails{}, fmt.Errorf("get AI SOC decision: %w", err)
	}
	return details, nil
}

func (p *Postgres) ListAISOCRequests(ctx context.Context, tenantID string, filter core.AISOCRequestFilter) ([]core.AISOCRequest, error) {
	args := []interface{}{tenantID}
	where := []string{"tenant_id=$1"}
	if filter.Status != "" {
		args = append(args, filter.Status)
		where = append(where, fmt.Sprintf("status=$%d", len(args)))
	}
	if filter.Function != "" {
		args = append(args, filter.Function)
		where = append(where, fmt.Sprintf("function=$%d", len(args)))
	}
	if filter.Provider != "" {
		args = append(args, filter.Provider)
		where = append(where, fmt.Sprintf("provider=$%d", len(args)))
	}
	if filter.RequestedBy != "" {
		args = append(args, filter.RequestedBy)
		where = append(where, fmt.Sprintf("requested_by=$%d", len(args)))
	}
	args = append(args, normalizedLimit(filter.Limit))
	rows, err := p.pool.Query(ctx, `SELECT `+aiRequestColumns+` FROM ai_soc_requests WHERE `+
		strings.Join(where, " AND ")+fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d", len(args)), args...)
	if err != nil {
		return nil, fmt.Errorf("list AI SOC requests: %w", err)
	}
	defer rows.Close()
	items := []core.AISOCRequest{}
	for rows.Next() {
		item, err := scanAISOCRequest(rows)
		if err != nil {
			return nil, fmt.Errorf("scan AI SOC request: %w", err)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (p *Postgres) ClaimAISOCRequest(ctx context.Context, workerID, tenantID string, lease time.Duration) (core.AISOCRequest, bool, error) {
	now := time.Now().UTC()
	request, err := scanAISOCRequest(p.pool.QueryRow(ctx, `WITH candidate AS (
		SELECT tenant_id,request_id FROM ai_soc_requests
		WHERE (status='QUEUED' OR (status='RUNNING' AND lease_expires_at<$3))
		AND ($2='' OR tenant_id=$2)
		ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1
	)
	UPDATE ai_soc_requests r SET status='RUNNING',lease_owner=$1,lease_expires_at=$4,
		attempt=attempt+1,started_at=COALESCE(started_at,$3),updated_at=$3,version=version+1
	FROM candidate c WHERE r.tenant_id=c.tenant_id AND r.request_id=c.request_id
	RETURNING `+prefixedColumns(aiRequestColumns, "r"), workerID, tenantID, now, now.Add(lease)))
	if errors.Is(err, pgx.ErrNoRows) {
		return core.AISOCRequest{}, false, nil
	}
	if err != nil {
		return core.AISOCRequest{}, false, fmt.Errorf("claim AI SOC request: %w", err)
	}
	return request, true, nil
}

func (p *Postgres) CompleteAISOCRequest(ctx context.Context, request core.AISOCRequest, workerID string) (core.AISOCRequest, error) {
	documents, _ := json.Marshal(request.ContextDocuments)
	recommendation, _ := json.Marshal(request.Recommendation)
	now := time.Now().UTC()
	item, err := scanAISOCRequest(p.pool.QueryRow(ctx, `UPDATE ai_soc_requests SET
		context_snapshot=$4,context_digest=$5,recommendation=$6,model=$7,status='SUCCEEDED',
		prompt_injection_detected=FALSE,redaction_count=$8,failure_class='',failure_detail='',
		lease_owner='',lease_expires_at=NULL,completed_at=$9,updated_at=$9,version=version+1
		WHERE tenant_id=$1 AND request_id=$2 AND lease_owner=$3 AND status='RUNNING'
		RETURNING `+aiRequestColumns, request.TenantID, request.ID, workerID, documents, request.ContextDigest,
		recommendation, request.Model, request.RedactionCount, now))
	if errors.Is(err, pgx.ErrNoRows) {
		return core.AISOCRequest{}, ErrVersionConflict
	}
	if err != nil {
		return core.AISOCRequest{}, fmt.Errorf("complete AI SOC request: %w", err)
	}
	return item, nil
}

func (p *Postgres) FinishAISOCRequestFailure(ctx context.Context, tenantID, requestID, workerID,
	status, class, detail string, documents []core.AISOCContextDocument, digest string,
	redactions int, injectionDetected bool) (core.AISOCRequest, error) {
	contextJSON, _ := json.Marshal(documents)
	now := time.Now().UTC()
	item, err := scanAISOCRequest(p.pool.QueryRow(ctx, `UPDATE ai_soc_requests SET
		context_snapshot=$4,context_digest=$5,status=$6,prompt_injection_detected=$7,
		redaction_count=$8,failure_class=$9,failure_detail=$10,lease_owner='',lease_expires_at=NULL,
		completed_at=$11,updated_at=$11,version=version+1
		WHERE tenant_id=$1 AND request_id=$2 AND lease_owner=$3 AND status='RUNNING'
		RETURNING `+aiRequestColumns, tenantID, requestID, workerID, contextJSON, digest, status,
		injectionDetected, redactions, class, detail, now))
	if errors.Is(err, pgx.ErrNoRows) {
		return core.AISOCRequest{}, ErrVersionConflict
	}
	if err != nil {
		return core.AISOCRequest{}, fmt.Errorf("fail AI SOC request: %w", err)
	}
	return item, nil
}

func (p *Postgres) CreateAISOCDecision(ctx context.Context, decision core.AISOCDecision) (core.AISOCDecision, error) {
	item, err := scanAISOCDecision(p.pool.QueryRow(ctx, `INSERT INTO ai_soc_decisions(
		tenant_id,decision_id,request_id,decision,reason,decided_by,created_at)
		SELECT $1,$2,$3,$4,$5,$6,$7 FROM ai_soc_requests
		WHERE tenant_id=$1 AND request_id=$3 AND status='SUCCEEDED'
		RETURNING `+aiDecisionColumns, decision.TenantID, decision.ID, decision.RequestID,
		decision.Decision, decision.Reason, decision.DecidedBy, decision.CreatedAt))
	if errors.Is(err, pgx.ErrNoRows) {
		return core.AISOCDecision{}, ErrNotFound
	}
	if err != nil {
		var postgresError *pgconn.PgError
		if errors.As(err, &postgresError) && postgresError.Code == "23505" {
			return core.AISOCDecision{}, ErrAlreadyExists
		}
		return core.AISOCDecision{}, fmt.Errorf("create AI SOC decision: %w", err)
	}
	return item, nil
}

type aiRow interface {
	Scan(...interface{}) error
}

func scanAISOCPolicy(row aiRow) (core.AISOCPolicy, error) {
	var item core.AISOCPolicy
	err := row.Scan(&item.TenantID, &item.Enabled, &item.CloudAllowed, &item.PIIRedaction,
		&item.MaximumContextItems, &item.LocalModel, &item.CloudModel, &item.Version,
		&item.UpdatedBy, &item.UpdatedAt)
	return item, err
}

func scanAISOCRequest(row aiRow) (core.AISOCRequest, error) {
	var item core.AISOCRequest
	var refs, documents, recommendation []byte
	var leaseExpires, startedAt, completedAt sql.NullTime
	err := row.Scan(&item.TenantID, &item.ID, &item.IdempotencyKey, &item.RequestHash, &item.Function,
		&item.Question, &refs, &documents, &item.ContextDigest, &item.Status, &item.Provider, &item.Model,
		&recommendation, &item.RequestedBy, &item.PromptInjectionDetected, &item.RedactionCount,
		&item.FailureClass, &item.FailureDetail, &item.Attempt, &item.Version, &item.LeaseOwner,
		&leaseExpires, &item.CreatedAt, &startedAt, &completedAt, &item.UpdatedAt)
	if err != nil {
		return core.AISOCRequest{}, err
	}
	if err := json.Unmarshal(refs, &item.ContextRefs); err != nil {
		return core.AISOCRequest{}, err
	}
	if err := json.Unmarshal(documents, &item.ContextDocuments); err != nil {
		return core.AISOCRequest{}, err
	}
	if string(recommendation) != "{}" {
		if err := json.Unmarshal(recommendation, &item.Recommendation); err != nil {
			return core.AISOCRequest{}, err
		}
	}
	if leaseExpires.Valid {
		item.LeaseExpiresAt = &leaseExpires.Time
	}
	if startedAt.Valid {
		item.StartedAt = &startedAt.Time
	}
	if completedAt.Valid {
		item.CompletedAt = &completedAt.Time
	}
	return item, nil
}

func scanAISOCDecision(row aiRow) (core.AISOCDecision, error) {
	var item core.AISOCDecision
	err := row.Scan(&item.TenantID, &item.ID, &item.RequestID, &item.Decision,
		&item.Reason, &item.DecidedBy, &item.CreatedAt)
	return item, err
}

func prefixedColumns(columns, prefix string) string {
	parts := strings.Split(columns, ",")
	for index, part := range parts {
		parts[index] = prefix + "." + strings.TrimSpace(part)
	}
	return strings.Join(parts, ",")
}
