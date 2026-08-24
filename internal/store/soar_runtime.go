package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/soar"
)

const soarApprovalColumns = `tenant_id,approval_id,execution_id,node_execution_id,risk_level,
	required_approvals,status,version,requested_by,requested_at,expires_at,decided_at`

const soarActionAttemptColumns = `tenant_id,action_attempt_id,execution_id,node_execution_id,
	idempotency_key,connector_id,action_type,risk_level,mode,status,request,result,error_class,
	error_detail,verification_status,compensation_status,created_at,updated_at`

func (p *Postgres) ClaimSOARNode(ctx context.Context, workerID, tenantScope string, lease time.Duration) (core.SOARWorkItem, bool, error) {
	workerID = strings.TrimSpace(workerID)
	tenantScope = strings.TrimSpace(tenantScope)
	if workerID == "" || lease <= 0 {
		return core.SOARWorkItem{}, false, fmt.Errorf("%w: worker identity and positive lease are required", soar.ErrInvalidExecution)
	}
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return core.SOARWorkItem{}, false, fmt.Errorf("begin SOAR claim: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	now := time.Now().UTC()
	if err := expireSOARApprovals(ctx, tx, now); err != nil {
		return core.SOARWorkItem{}, false, err
	}
	var tenantID, nodeExecutionID string
	err = tx.QueryRow(ctx, `SELECT n.tenant_id,n.node_execution_id
		FROM soar_node_executions n
		JOIN soar_executions e ON e.tenant_id=n.tenant_id AND e.execution_id=n.execution_id
		WHERE e.status IN ('QUEUED','RUNNING','WAITING_APPROVAL','WAITING_MANUAL')
		  AND ($2='' OR n.tenant_id=$2) AND n.available_at <= $1
		  AND (n.status='READY' OR (n.status='RUNNING' AND COALESCE(n.lease_until,'-infinity'::timestamptz) <= $1))
		ORDER BY n.available_at,n.created_at,n.node_execution_id
		FOR UPDATE OF n SKIP LOCKED LIMIT 1`, now, tenantScope).Scan(&tenantID, &nodeExecutionID)
	if errors.Is(err, pgx.ErrNoRows) {
		return core.SOARWorkItem{}, false, nil
	}
	if err != nil {
		return core.SOARWorkItem{}, false, fmt.Errorf("select SOAR work item: %w", err)
	}
	node, err := scanSOARNodeExecution(tx.QueryRow(ctx, `UPDATE soar_node_executions SET
		status='RUNNING',attempt=attempt+1,lease_owner=$3,lease_until=$4,
		started_at=COALESCE(started_at,$5),updated_at=$5
		WHERE tenant_id=$1 AND node_execution_id=$2 RETURNING `+soarNodeColumns,
		tenantID, nodeExecutionID, workerID, now.Add(lease), now))
	if err != nil {
		return core.SOARWorkItem{}, false, fmt.Errorf("lease SOAR work item: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE soar_executions SET status='RUNNING',version=version+1,
		started_at=COALESCE(started_at,$3),updated_at=$3
		WHERE tenant_id=$1 AND execution_id=$2`, tenantID, node.ExecutionID, now); err != nil {
		return core.SOARWorkItem{}, false, fmt.Errorf("mark SOAR execution running: %w", err)
	}
	execution, err := scanSOARExecution(tx.QueryRow(ctx, `SELECT `+soarExecutionColumns+`
		FROM soar_executions WHERE tenant_id=$1 AND execution_id=$2`, tenantID, node.ExecutionID))
	if err != nil {
		return core.SOARWorkItem{}, false, fmt.Errorf("load claimed SOAR execution: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return core.SOARWorkItem{}, false, fmt.Errorf("commit SOAR claim: %w", err)
	}
	return core.SOARWorkItem{Execution: execution, Node: node}, true, nil
}

func (p *Postgres) CompleteSOARNode(ctx context.Context, tenantID, nodeExecutionID, workerID string,
	output map[string]interface{}) error {
	payload, err := encodeSOARObject(output)
	if err != nil {
		return err
	}
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin SOAR node completion: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	now := time.Now().UTC()
	var executionID string
	err = tx.QueryRow(ctx, `UPDATE soar_node_executions SET status='SUCCEEDED',output=$4,
		error_code='',error_detail='',lease_owner='',lease_until=NULL,completed_at=$5,updated_at=$5
		WHERE tenant_id=$1 AND node_execution_id=$2 AND status='RUNNING' AND lease_owner=$3
		RETURNING execution_id`, tenantID, nodeExecutionID, workerID, payload, now).Scan(&executionID)
	if err != nil {
		return leasedSOARTransitionError(err, "complete")
	}
	if err := promoteAndReconcileSOAR(ctx, tx, tenantID, executionID, now); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit SOAR node completion: %w", err)
	}
	return nil
}

func (p *Postgres) DeferSOARNode(ctx context.Context, tenantID, nodeExecutionID, workerID string,
	availableAt time.Time, output map[string]interface{}) error {
	payload, err := encodeSOARObject(output)
	if err != nil {
		return err
	}
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin SOAR node deferral: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	now := time.Now().UTC()
	var executionID string
	err = tx.QueryRow(ctx, `UPDATE soar_node_executions SET status='READY',available_at=$4,output=$5,
		lease_owner='',lease_until=NULL,updated_at=$6
		WHERE tenant_id=$1 AND node_execution_id=$2 AND status='RUNNING' AND lease_owner=$3
		RETURNING execution_id`, tenantID, nodeExecutionID, workerID, availableAt.UTC(), payload, now).Scan(&executionID)
	if err != nil {
		return leasedSOARTransitionError(err, "defer")
	}
	if _, err := tx.Exec(ctx, `UPDATE soar_executions SET status='RUNNING',version=version+1,updated_at=$3
		WHERE tenant_id=$1 AND execution_id=$2`, tenantID, executionID, now); err != nil {
		return fmt.Errorf("update deferred SOAR execution: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit SOAR node deferral: %w", err)
	}
	return nil
}

func (p *Postgres) RetrySOARNode(ctx context.Context, tenantID, nodeExecutionID, workerID string,
	availableAt time.Time, code, detail string) error {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin SOAR node retry: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	now := time.Now().UTC()
	var executionID string
	err = tx.QueryRow(ctx, `UPDATE soar_node_executions SET status='READY',available_at=$4,
		error_code=$5,error_detail=$6,lease_owner='',lease_until=NULL,updated_at=$7
		WHERE tenant_id=$1 AND node_execution_id=$2 AND status='RUNNING' AND lease_owner=$3
		RETURNING execution_id`, tenantID, nodeExecutionID, workerID, availableAt.UTC(),
		strings.TrimSpace(code), strings.TrimSpace(detail), now).Scan(&executionID)
	if err != nil {
		return leasedSOARTransitionError(err, "retry")
	}
	if _, err := tx.Exec(ctx, `UPDATE soar_executions SET status='RUNNING',version=version+1,updated_at=$3
		WHERE tenant_id=$1 AND execution_id=$2`, tenantID, executionID, now); err != nil {
		return fmt.Errorf("update retried SOAR execution: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit SOAR node retry: %w", err)
	}
	return nil
}

func (p *Postgres) FailSOARNode(ctx context.Context, tenantID, nodeExecutionID, workerID, code, detail string) error {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin SOAR node failure: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	now := time.Now().UTC()
	var executionID string
	err = tx.QueryRow(ctx, `UPDATE soar_node_executions SET status='FAILED',error_code=$4,error_detail=$5,
		lease_owner='',lease_until=NULL,completed_at=$6,updated_at=$6
		WHERE tenant_id=$1 AND node_execution_id=$2 AND status='RUNNING' AND lease_owner=$3
		RETURNING execution_id`, tenantID, nodeExecutionID, workerID, strings.TrimSpace(code),
		strings.TrimSpace(detail), now).Scan(&executionID)
	if err != nil {
		return leasedSOARTransitionError(err, "fail")
	}
	if err := promoteAndReconcileSOAR(ctx, tx, tenantID, executionID, now); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit SOAR node failure: %w", err)
	}
	return nil
}

func (p *Postgres) RequestSOARApproval(ctx context.Context, item core.SOARWorkItem, riskLevel, required int,
	expiresAt time.Time) (core.SOARApproval, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return core.SOARApproval{}, fmt.Errorf("begin SOAR approval request: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var executionID, status, leaseOwner string
	err = tx.QueryRow(ctx, `SELECT execution_id,status,lease_owner FROM soar_node_executions
		WHERE tenant_id=$1 AND node_execution_id=$2 FOR UPDATE`, item.Node.TenantID, item.Node.ID).
		Scan(&executionID, &status, &leaseOwner)
	if errors.Is(err, pgx.ErrNoRows) {
		return core.SOARApproval{}, ErrNotFound
	}
	if err != nil {
		return core.SOARApproval{}, fmt.Errorf("lock SOAR approval node: %w", err)
	}
	if status != "RUNNING" || leaseOwner != item.Node.LeaseOwner || executionID != item.Execution.ID {
		return core.SOARApproval{}, fmt.Errorf("%w: approval node lease changed", soar.ErrInvalidState)
	}
	now := time.Now().UTC()
	approvalID := core.NewID("sap")
	if _, err := tx.Exec(ctx, `INSERT INTO soar_approvals(
		tenant_id,approval_id,execution_id,node_execution_id,risk_level,required_approvals,status,
		requested_by,requested_at,expires_at)
		VALUES($1,$2,$3,$4,$5,$6,'PENDING',$7,$8,$9)
		ON CONFLICT (tenant_id,node_execution_id) DO NOTHING`,
		item.Node.TenantID, approvalID, executionID, item.Node.ID, riskLevel, required,
		item.Execution.TriggeredBy, now, expiresAt.UTC()); err != nil {
		return core.SOARApproval{}, fmt.Errorf("insert SOAR approval: %w", err)
	}
	if err := tx.QueryRow(ctx, `SELECT approval_id FROM soar_approvals
		WHERE tenant_id=$1 AND node_execution_id=$2`, item.Node.TenantID, item.Node.ID).Scan(&approvalID); err != nil {
		return core.SOARApproval{}, fmt.Errorf("resolve SOAR approval: %w", err)
	}
	tag, err := tx.Exec(ctx, `UPDATE soar_node_executions SET status='WAITING_APPROVAL',
		lease_owner='',lease_until=NULL,updated_at=$4
		WHERE tenant_id=$1 AND node_execution_id=$2 AND status='RUNNING' AND lease_owner=$3`,
		item.Node.TenantID, item.Node.ID, item.Node.LeaseOwner, now)
	if err != nil {
		return core.SOARApproval{}, fmt.Errorf("wait for SOAR approval: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return core.SOARApproval{}, fmt.Errorf("%w: approval node lease changed", soar.ErrInvalidState)
	}
	if err := promoteAndReconcileSOAR(ctx, tx, item.Node.TenantID, executionID, now); err != nil {
		return core.SOARApproval{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return core.SOARApproval{}, fmt.Errorf("commit SOAR approval request: %w", err)
	}
	return p.getSOARApproval(ctx, item.Node.TenantID, approvalID)
}

func (p *Postgres) RequestSOARManualTask(ctx context.Context, item core.SOARWorkItem) error {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin SOAR manual wait: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	now := time.Now().UTC()
	tag, err := tx.Exec(ctx, `UPDATE soar_node_executions SET status='WAITING_MANUAL',
		lease_owner='',lease_until=NULL,updated_at=$4
		WHERE tenant_id=$1 AND node_execution_id=$2 AND status='RUNNING' AND lease_owner=$3`,
		item.Node.TenantID, item.Node.ID, item.Node.LeaseOwner, now)
	if err != nil {
		return fmt.Errorf("wait for SOAR manual task: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("%w: manual task node lease changed", soar.ErrInvalidState)
	}
	if err := promoteAndReconcileSOAR(ctx, tx, item.Node.TenantID, item.Execution.ID, now); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit SOAR manual wait: %w", err)
	}
	return nil
}

func (p *Postgres) BeginSOARAction(ctx context.Context, attempt core.SOARActionAttempt) (core.SOARActionAttempt, bool, error) {
	request, err := encodeSOARObject(attempt.Request)
	if err != nil {
		return core.SOARActionAttempt{}, false, err
	}
	result, err := encodeSOARObject(attempt.Result)
	if err != nil {
		return core.SOARActionAttempt{}, false, err
	}
	stored, err := scanSOARActionAttempt(p.pool.QueryRow(ctx, `INSERT INTO soar_action_attempts(
		tenant_id,action_attempt_id,execution_id,node_execution_id,idempotency_key,connector_id,
		action_type,risk_level,mode,status,request,result,error_class,error_detail,
		verification_status,compensation_status,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
		ON CONFLICT (tenant_id,idempotency_key) DO NOTHING RETURNING `+soarActionAttemptColumns,
		attempt.TenantID, attempt.ID, attempt.ExecutionID, attempt.NodeExecutionID, attempt.IdempotencyKey,
		attempt.ConnectorID, attempt.ActionType, attempt.RiskLevel, attempt.Mode, attempt.Status, request, result,
		attempt.ErrorClass, attempt.ErrorDetail, attempt.VerificationStatus, attempt.CompensationStatus,
		attempt.CreatedAt, attempt.UpdatedAt))
	if err == nil {
		return stored, true, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return core.SOARActionAttempt{}, false, fmt.Errorf("begin SOAR action: %w", err)
	}
	stored, err = scanSOARActionAttempt(p.pool.QueryRow(ctx, `SELECT `+soarActionAttemptColumns+`
		FROM soar_action_attempts WHERE tenant_id=$1 AND idempotency_key=$2`,
		attempt.TenantID, attempt.IdempotencyKey))
	if err != nil {
		return core.SOARActionAttempt{}, false, fmt.Errorf("load idempotent SOAR action: %w", err)
	}
	return stored, false, nil
}

func (p *Postgres) FinishSOARAction(ctx context.Context, tenantID, attemptID, status string,
	result map[string]interface{}, errorClass, errorDetail, verificationStatus string) (core.SOARActionAttempt, error) {
	payload, err := encodeSOARObject(result)
	if err != nil {
		return core.SOARActionAttempt{}, err
	}
	item, err := scanSOARActionAttempt(p.pool.QueryRow(ctx, `UPDATE soar_action_attempts SET
		status=$3,result=$4,error_class=$5,error_detail=$6,verification_status=$7,updated_at=$8
		WHERE tenant_id=$1 AND action_attempt_id=$2 RETURNING `+soarActionAttemptColumns,
		tenantID, attemptID, strings.ToUpper(strings.TrimSpace(status)), payload, strings.TrimSpace(errorClass),
		strings.TrimSpace(errorDetail), strings.TrimSpace(verificationStatus), time.Now().UTC()))
	if errors.Is(err, pgx.ErrNoRows) {
		return core.SOARActionAttempt{}, ErrNotFound
	}
	if err != nil {
		return core.SOARActionAttempt{}, fmt.Errorf("finish SOAR action: %w", err)
	}
	return item, nil
}

func (p *Postgres) ListSOARApprovals(ctx context.Context, tenantID string,
	filter core.SOARApprovalFilter) ([]core.SOARApproval, error) {
	if filter.Limit <= 0 || filter.Limit > 500 {
		filter.Limit = 100
	}
	rows, err := p.pool.Query(ctx, `SELECT `+soarApprovalColumns+` FROM soar_approvals
		WHERE tenant_id=$1 AND ($2='' OR status=$2) AND ($3='' OR execution_id=$3)
		ORDER BY requested_at DESC,approval_id LIMIT $4`,
		tenantID, filter.Status, filter.ExecutionID, filter.Limit)
	if err != nil {
		return nil, fmt.Errorf("list SOAR approvals: %w", err)
	}
	items := []core.SOARApproval{}
	for rows.Next() {
		item, scanErr := scanSOARApproval(rows)
		if scanErr != nil {
			rows.Close()
			return nil, fmt.Errorf("scan SOAR approval: %w", scanErr)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	for index := range items {
		decisions, err := p.listSOARApprovalDecisions(ctx, tenantID, items[index].ID)
		if err != nil {
			return nil, err
		}
		items[index].Decisions = decisions
	}
	return items, nil
}

func (p *Postgres) DecideSOARApproval(ctx context.Context, tenantID, approvalID, approver string,
	command core.SOARApprovalCommand) (core.SOARApproval, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return core.SOARApproval{}, fmt.Errorf("begin SOAR approval decision: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	approval, err := scanSOARApproval(tx.QueryRow(ctx, `SELECT `+soarApprovalColumns+`
		FROM soar_approvals WHERE tenant_id=$1 AND approval_id=$2 FOR UPDATE`, tenantID, approvalID))
	if errors.Is(err, pgx.ErrNoRows) {
		return core.SOARApproval{}, ErrNotFound
	}
	if err != nil {
		return core.SOARApproval{}, fmt.Errorf("lock SOAR approval: %w", err)
	}
	now := time.Now().UTC()
	if approval.Version != command.Version {
		return core.SOARApproval{}, fmt.Errorf("%w: expected version %d, current version %d", soar.ErrApprovalVersionConflict, command.Version, approval.Version)
	}
	if approval.Status != core.ApprovalStatusPending {
		return core.SOARApproval{}, fmt.Errorf("%w: approval is already %s", soar.ErrInvalidState, approval.Status)
	}
	if !now.Before(approval.ExpiresAt) {
		if _, err := tx.Exec(ctx, `UPDATE soar_approvals SET status='EXPIRED',decided_at=$3,version=version+1
			WHERE tenant_id=$1 AND approval_id=$2`, tenantID, approvalID, now); err != nil {
			return core.SOARApproval{}, err
		}
		if _, err := tx.Exec(ctx, `UPDATE soar_node_executions SET status='FAILED',
			error_code='approval_expired',error_detail='approval window expired',completed_at=$3,updated_at=$3
			WHERE tenant_id=$1 AND node_execution_id=$2 AND status='WAITING_APPROVAL'`,
			tenantID, approval.NodeExecutionID, now); err != nil {
			return core.SOARApproval{}, err
		}
		if err := promoteAndReconcileSOAR(ctx, tx, tenantID, approval.ExecutionID, now); err != nil {
			return core.SOARApproval{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return core.SOARApproval{}, err
		}
		return core.SOARApproval{}, fmt.Errorf("%w: approval expired", soar.ErrInvalidState)
	}
	if approval.RequestedBy == approver {
		return core.SOARApproval{}, fmt.Errorf("%w: execution initiator cannot approve their own action", soar.ErrInvalidState)
	}
	tag, err := tx.Exec(ctx, `INSERT INTO soar_approval_decisions(
		tenant_id,approval_id,approver,decision,reason,decided_at)
		VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`,
		tenantID, approvalID, approver, command.Decision, command.Reason, now)
	if err != nil {
		return core.SOARApproval{}, fmt.Errorf("record SOAR approval decision: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return core.SOARApproval{}, ErrAlreadyExists
	}
	var finalStatus core.ApprovalStatus
	if command.Decision == core.ApprovalDecisionReject {
		finalStatus = core.ApprovalStatusRejected
	} else {
		var approvals int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM soar_approval_decisions
			WHERE tenant_id=$1 AND approval_id=$2 AND decision='APPROVE'`,
			tenantID, approvalID).Scan(&approvals); err != nil {
			return core.SOARApproval{}, fmt.Errorf("count SOAR approvals: %w", err)
		}
		if approvals >= approval.RequiredApprovals {
			finalStatus = core.ApprovalStatusApproved
		}
	}
	newStatus := core.ApprovalStatusPending
	if finalStatus != "" {
		newStatus = finalStatus
	}
	if finalStatus != "" {
		if _, err := tx.Exec(ctx, `UPDATE soar_approvals SET status=$3,decided_at=$4,version=version+1
			WHERE tenant_id=$1 AND approval_id=$2`, tenantID, approvalID, finalStatus, now); err != nil {
			return core.SOARApproval{}, fmt.Errorf("finalize SOAR approval: %w", err)
		}
		if finalStatus == core.ApprovalStatusRejected {
			tag, err = tx.Exec(ctx, `UPDATE soar_node_executions SET status='FAILED',
				error_code='approval_rejected',error_detail=$3,completed_at=$4,updated_at=$4
				WHERE tenant_id=$1 AND node_execution_id=$2 AND status='WAITING_APPROVAL'`,
				tenantID, approval.NodeExecutionID, command.Reason, now)
		} else {
			output, _ := json.Marshal(map[string]interface{}{
				"approval_id": approvalID, "approved": true, "required_approvals": approval.RequiredApprovals,
			})
			tag, err = tx.Exec(ctx, `UPDATE soar_node_executions SET status='SUCCEEDED',output=$3,
				completed_at=$4,updated_at=$4 WHERE tenant_id=$1 AND node_execution_id=$2
				AND status='WAITING_APPROVAL'`, tenantID, approval.NodeExecutionID, output, now)
		}
		if err != nil {
			return core.SOARApproval{}, fmt.Errorf("resume SOAR approval node: %w", err)
		}
		if tag.RowsAffected() != 1 {
			return core.SOARApproval{}, fmt.Errorf("%w: approval node is no longer waiting", soar.ErrInvalidState)
		}
		if err := promoteAndReconcileSOAR(ctx, tx, tenantID, approval.ExecutionID, now); err != nil {
			return core.SOARApproval{}, err
		}
	} else if _, err := tx.Exec(ctx, `UPDATE soar_approvals SET version=version+1
		WHERE tenant_id=$1 AND approval_id=$2`, tenantID, approvalID); err != nil {
		return core.SOARApproval{}, fmt.Errorf("advance SOAR approval version: %w", err)
	}
	actorType := strings.TrimSpace(command.ActorType)
	if actorType == "" {
		actorType = "USER"
	}
	correlationID := strings.TrimSpace(command.CorrelationID)
	if correlationID == "" {
		correlationID = strings.TrimSpace(command.RequestID)
	}
	if _, err := appendAuditTx(ctx, tx, core.AuditEntry{
		TenantID: tenantID, Actor: approver,
		Action:       "soar.approval." + strings.ToLower(string(command.Decision)),
		ResourceType: "soar_approval", ResourceID: approvalID, Outcome: "SUCCESS",
		RequestID: command.RequestID, Metadata: map[string]interface{}{
			"actor_id": approver, "actor_type": actorType, "tenant_id": tenantID,
			"approval_request_id": approvalID, "playbook_run_id": approval.ExecutionID,
			"action_id": approval.NodeExecutionID, "decision": command.Decision,
			"previous_status": approval.Status, "new_status": newStatus, "reason": command.Reason,
			"timestamp": now, "correlation_id": correlationID, "request_id": command.RequestID,
			"optimistic_version": approval.Version + 1, "source": command.Source,
		},
	}); err != nil {
		return core.SOARApproval{}, fmt.Errorf("append SOAR approval audit: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return core.SOARApproval{}, fmt.Errorf("commit SOAR approval decision: %w", err)
	}
	return p.getSOARApproval(ctx, tenantID, approvalID)
}

func (p *Postgres) CompleteSOARManualTask(ctx context.Context, tenantID, executionID, nodeID string,
	output map[string]interface{}) (core.SOARExecution, error) {
	payload, err := encodeSOARObject(output)
	if err != nil {
		return core.SOARExecution{}, err
	}
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return core.SOARExecution{}, fmt.Errorf("begin SOAR manual completion: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	now := time.Now().UTC()
	tag, err := tx.Exec(ctx, `UPDATE soar_node_executions SET status='SUCCEEDED',output=$4,
		completed_at=$5,updated_at=$5 WHERE tenant_id=$1 AND execution_id=$2 AND node_id=$3
		AND status='WAITING_MANUAL'`, tenantID, executionID, nodeID, payload, now)
	if err != nil {
		return core.SOARExecution{}, fmt.Errorf("complete SOAR manual task: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return core.SOARExecution{}, fmt.Errorf("%w: manual task is not waiting", soar.ErrInvalidState)
	}
	if err := promoteAndReconcileSOAR(ctx, tx, tenantID, executionID, now); err != nil {
		return core.SOARExecution{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return core.SOARExecution{}, fmt.Errorf("commit SOAR manual completion: %w", err)
	}
	return p.GetSOARExecution(ctx, tenantID, executionID)
}

func (p *Postgres) ListSOARActionAttempts(ctx context.Context, tenantID, executionID string,
	limit int) ([]core.SOARActionAttempt, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := p.pool.Query(ctx, `SELECT `+soarActionAttemptColumns+` FROM soar_action_attempts
		WHERE tenant_id=$1 AND execution_id=$2 ORDER BY created_at,action_attempt_id LIMIT $3`,
		tenantID, executionID, limit)
	if err != nil {
		return nil, fmt.Errorf("list SOAR action attempts: %w", err)
	}
	defer rows.Close()
	items := []core.SOARActionAttempt{}
	for rows.Next() {
		item, scanErr := scanSOARActionAttempt(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("scan SOAR action attempt: %w", scanErr)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func promoteAndReconcileSOAR(ctx context.Context, tx pgx.Tx, tenantID, executionID string, now time.Time) error {
	if _, err := tx.Exec(ctx, `UPDATE soar_node_executions candidate SET
		status='READY',available_at=$3,updated_at=$3
		WHERE candidate.tenant_id=$1 AND candidate.execution_id=$2 AND candidate.status='PENDING'
		  AND NOT EXISTS (
			SELECT 1 FROM jsonb_array_elements_text(candidate.depends_on) dependency(node_id)
			LEFT JOIN soar_node_executions parent
			  ON parent.tenant_id=candidate.tenant_id AND parent.execution_id=candidate.execution_id
			 AND parent.node_id=dependency.node_id
			WHERE parent.node_execution_id IS NULL OR parent.status NOT IN ('SUCCEEDED','SKIPPED')
		  )`, tenantID, executionID, now); err != nil {
		return fmt.Errorf("promote SOAR DAG nodes: %w", err)
	}
	var failed, active, waitingApproval, waitingManual int
	if err := tx.QueryRow(ctx, `SELECT
		count(*) FILTER (WHERE status='FAILED'),
		count(*) FILTER (WHERE status IN ('PENDING','READY','RUNNING','WAITING_APPROVAL','WAITING_MANUAL')),
		count(*) FILTER (WHERE status='WAITING_APPROVAL'),
		count(*) FILTER (WHERE status='WAITING_MANUAL')
		FROM soar_node_executions WHERE tenant_id=$1 AND execution_id=$2`,
		tenantID, executionID).Scan(&failed, &active, &waitingApproval, &waitingManual); err != nil {
		return fmt.Errorf("summarize SOAR DAG: %w", err)
	}
	status := core.SOARExecutionRunning
	completed := false
	switch {
	case failed > 0:
		status = core.SOARExecutionFailed
		completed = true
		if _, err := tx.Exec(ctx, `UPDATE soar_node_executions SET status='CANCELLED',
			lease_owner='',lease_until=NULL,completed_at=$3,updated_at=$3
			WHERE tenant_id=$1 AND execution_id=$2
			  AND status IN ('PENDING','READY','RUNNING','WAITING_APPROVAL','WAITING_MANUAL')`,
			tenantID, executionID, now); err != nil {
			return fmt.Errorf("cancel failed SOAR branches: %w", err)
		}
	case active == 0:
		status = core.SOARExecutionSucceeded
		completed = true
	case waitingApproval > 0:
		status = core.SOARExecutionWaitingApproval
	case waitingManual > 0:
		status = core.SOARExecutionWaitingManual
	}
	var completedAt interface{}
	if completed {
		completedAt = now
	}
	tag, err := tx.Exec(ctx, `UPDATE soar_executions SET status=$3,version=version+1,
		updated_at=$4,completed_at=$5 WHERE tenant_id=$1 AND execution_id=$2`,
		tenantID, executionID, status, now, completedAt)
	if err != nil {
		return fmt.Errorf("reconcile SOAR execution: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrNotFound
	}
	return nil
}

func expireSOARApprovals(ctx context.Context, tx pgx.Tx, now time.Time) error {
	rows, err := tx.Query(ctx, `UPDATE soar_approvals SET status='EXPIRED',decided_at=$1,version=version+1
		WHERE status='PENDING' AND expires_at <= $1
		RETURNING tenant_id,execution_id,node_execution_id`, now)
	if err != nil {
		return fmt.Errorf("expire SOAR approvals: %w", err)
	}
	type expiredApproval struct {
		tenantID, executionID, nodeExecutionID string
	}
	expired := []expiredApproval{}
	for rows.Next() {
		var item expiredApproval
		if err := rows.Scan(&item.tenantID, &item.executionID, &item.nodeExecutionID); err != nil {
			rows.Close()
			return err
		}
		expired = append(expired, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	executions := map[string]expiredApproval{}
	for _, item := range expired {
		if _, err := tx.Exec(ctx, `UPDATE soar_node_executions SET status='FAILED',
			error_code='approval_expired',error_detail='approval window expired',completed_at=$3,updated_at=$3
			WHERE tenant_id=$1 AND node_execution_id=$2 AND status='WAITING_APPROVAL'`,
			item.tenantID, item.nodeExecutionID, now); err != nil {
			return err
		}
		executions[item.tenantID+"|"+item.executionID] = item
	}
	for _, item := range executions {
		if err := promoteAndReconcileSOAR(ctx, tx, item.tenantID, item.executionID, now); err != nil {
			return err
		}
	}
	return nil
}

func (p *Postgres) getSOARApproval(ctx context.Context, tenantID, approvalID string) (core.SOARApproval, error) {
	item, err := scanSOARApproval(p.pool.QueryRow(ctx, `SELECT `+soarApprovalColumns+`
		FROM soar_approvals WHERE tenant_id=$1 AND approval_id=$2`, tenantID, approvalID))
	if errors.Is(err, pgx.ErrNoRows) {
		return core.SOARApproval{}, ErrNotFound
	}
	if err != nil {
		return core.SOARApproval{}, fmt.Errorf("get SOAR approval: %w", err)
	}
	item.Decisions, err = p.listSOARApprovalDecisions(ctx, tenantID, approvalID)
	return item, err
}

func (p *Postgres) listSOARApprovalDecisions(ctx context.Context, tenantID, approvalID string) ([]core.SOARApprovalDecision, error) {
	rows, err := p.pool.Query(ctx, `SELECT approver,decision,reason,decided_at
		FROM soar_approval_decisions WHERE tenant_id=$1 AND approval_id=$2
		ORDER BY decided_at,approver`, tenantID, approvalID)
	if err != nil {
		return nil, fmt.Errorf("list SOAR approval decisions: %w", err)
	}
	defer rows.Close()
	items := []core.SOARApprovalDecision{}
	for rows.Next() {
		var item core.SOARApprovalDecision
		var decision string
		if err := rows.Scan(&item.Approver, &decision, &item.Reason, &item.DecidedAt); err != nil {
			return nil, err
		}
		item.Decision = core.ApprovalDecision(decision)
		items = append(items, item)
	}
	return items, rows.Err()
}

func scanSOARApproval(row threatRow) (core.SOARApproval, error) {
	var item core.SOARApproval
	var status string
	err := row.Scan(&item.TenantID, &item.ID, &item.ExecutionID, &item.NodeExecutionID,
		&item.RiskLevel, &item.RequiredApprovals, &status, &item.Version, &item.RequestedBy,
		&item.RequestedAt, &item.ExpiresAt, &item.DecidedAt)
	item.Status = core.ApprovalStatus(status)
	item.Decisions = []core.SOARApprovalDecision{}
	return item, err
}

func scanSOARActionAttempt(row threatRow) (core.SOARActionAttempt, error) {
	var item core.SOARActionAttempt
	var request, result []byte
	err := row.Scan(&item.TenantID, &item.ID, &item.ExecutionID, &item.NodeExecutionID,
		&item.IdempotencyKey, &item.ConnectorID, &item.ActionType, &item.RiskLevel, &item.Mode,
		&item.Status, &request, &result, &item.ErrorClass, &item.ErrorDetail,
		&item.VerificationStatus, &item.CompensationStatus, &item.CreatedAt, &item.UpdatedAt)
	if err != nil {
		return core.SOARActionAttempt{}, err
	}
	if err := json.Unmarshal(request, &item.Request); err != nil {
		return core.SOARActionAttempt{}, fmt.Errorf("decode SOAR action request: %w", err)
	}
	if err := json.Unmarshal(result, &item.Result); err != nil {
		return core.SOARActionAttempt{}, fmt.Errorf("decode SOAR action result: %w", err)
	}
	return item, nil
}

func encodeSOARObject(value map[string]interface{}) ([]byte, error) {
	if value == nil {
		value = map[string]interface{}{}
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("%w: SOAR payload is not valid JSON", soar.ErrInvalidExecution)
	}
	if len(payload) > 1<<20 {
		return nil, fmt.Errorf("%w: SOAR payload exceeds 1 MiB", soar.ErrInvalidExecution)
	}
	return payload, nil
}

func leasedSOARTransitionError(err error, operation string) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("%w: cannot %s a node without its active lease", soar.ErrInvalidState, operation)
	}
	return fmt.Errorf("%s SOAR node: %w", operation, err)
}
