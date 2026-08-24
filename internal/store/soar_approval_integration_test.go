package store

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/soar"
)

type countingApprovalExecutor struct {
	mu    sync.Mutex
	calls map[string]int
}

func (e *countingApprovalExecutor) Execute(_ context.Context, request soar.ActionRequest) (soar.ActionResult, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.calls == nil {
		e.calls = map[string]int{}
	}
	e.calls[request.Attempt.IdempotencyKey]++
	return soar.ActionResult{Output: map[string]interface{}{"executed": true, "idempotency_key": request.Attempt.IdempotencyKey}, VerificationStatus: "VERIFIED"}, nil
}

func (e *countingApprovalExecutor) total() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	total := 0
	for _, count := range e.calls {
		total += count
	}
	return total
}

func createApprovalRuntime(t *testing.T, required int) (*Postgres, *soar.Service, string, core.SOARExecution, core.SOARApproval) {
	t.Helper()
	databaseURL := os.Getenv("KCSP_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("KCSP_TEST_DATABASE_URL is required for PostgreSQL approval runtime tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	repository, err := OpenPostgres(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(repository.Close)
	tenantID := "approval-" + core.NewID("tenant")
	if err := repository.EnsureTenant(ctx, tenantID, "Approval Runtime Test"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		_ = repository.ResetTenant(cleanup, tenantID)
	})
	service := soar.NewService(repository, nil)
	spec := core.SOARPlaybookSpec{SchemaVersion: "1.0", Trigger: core.SOARTrigger{Type: "MANUAL"}, Nodes: []core.SOARNode{
		{ID: "approve", Type: core.SOARNodeApproval, Name: "Independent SOC approval", Config: map[string]interface{}{"required_approvals": required}},
		{ID: "protected", Type: core.SOARNodeAction, Name: "Protected containment action", DependsOn: []string{"approve"}, Config: map[string]interface{}{
			"action_type": "kcsp.enrich.threat_intel", "mode": "LIVE", "connector_id": "kcsp-internal",
		}},
	}}
	details, err := service.CreatePlaybook(ctx, tenantID, "soar-engineer", soar.PlaybookDraft{Name: "Approval runtime closure", Spec: spec})
	if err != nil || !details.Versions[0].Validation.Valid {
		t.Fatalf("create playbook: %+v err=%v", details, err)
	}
	if _, err = service.PublishVersion(ctx, tenantID, details.Playbook.ID, 1, "soar-engineer"); err != nil {
		t.Fatal(err)
	}
	execution, created, err := service.StartExecution(ctx, tenantID, "execution-initiator", soar.ExecutionRequest{
		PlaybookID: details.Playbook.ID, RequestID: "approval-runtime-" + core.NewID("request"), TriggerType: "MANUAL",
	})
	if err != nil || !created {
		t.Fatalf("start execution: %+v created=%v err=%v", execution, created, err)
	}
	worker := soar.NewWorker(repository, nil, nil, soar.WorkerConfig{ID: "approval-worker-before-restart", TenantID: tenantID, Lease: time.Second}, nil)
	deadline := time.Now().Add(time.Second)
	for {
		worked, processErr := worker.ProcessOne(ctx)
		if processErr != nil {
			t.Fatalf("request approval: %v", processErr)
		}
		if worked {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("request approval: worker did not claim the ready node")
		}
		time.Sleep(10 * time.Millisecond)
	}
	approvals, err := service.Approvals(ctx, tenantID, core.SOARApprovalFilter{Status: "PENDING", ExecutionID: execution.ID, Limit: 10})
	if err != nil || len(approvals) != 1 || approvals[0].Version != 1 {
		t.Fatalf("pending approval: %+v err=%v", approvals, err)
	}
	return repository, service, tenantID, execution, approvals[0]
}

func approvalRequest(decision core.ApprovalDecision, reason string, version int, requestID string) soar.ApprovalDecisionRequest {
	return soar.ApprovalDecisionRequest{Decision: decision, Reason: reason, Version: version, RequestID: requestID,
		CorrelationID: requestID, ActorType: "USER", Source: map[string]interface{}{"transport": "TEST"}}
}

func TestPostgresSOARApprovalApproveResumesExactlyOnceAfterWorkerRestart(t *testing.T) {
	repository, service, tenantID, execution, approval := createApprovalRuntime(t, 1)
	ctx := context.Background()
	approved, err := service.DecideApproval(ctx, tenantID, approval.ID, "soc-manager", approvalRequest(core.ApprovalDecisionApprove, "Containment scope verified", approval.Version, "req-approve"))
	if err != nil || approved.Status != core.ApprovalStatusApproved || approved.Version != 2 {
		t.Fatalf("approve: %+v err=%v", approved, err)
	}
	if _, err := service.DecideApproval(ctx, tenantID, approval.ID, "soc-manager", approvalRequest(core.ApprovalDecisionApprove, "Duplicate", approval.Version, "req-duplicate")); !errors.Is(err, soar.ErrApprovalVersionConflict) {
		t.Fatalf("duplicate approve did not conflict: %v", err)
	}

	executor := &countingApprovalExecutor{}
	restartedWorker := soar.NewWorker(repository, nil, executor, soar.WorkerConfig{ID: "approval-worker-after-restart", TenantID: tenantID, Lease: time.Second}, nil)
	if worked, err := restartedWorker.ProcessOne(ctx); err != nil || !worked {
		t.Fatalf("resumed protected action: worked=%v err=%v", worked, err)
	}
	if worked, err := restartedWorker.ProcessOne(ctx); err != nil || worked {
		t.Fatalf("protected action was claimable twice: worked=%v err=%v", worked, err)
	}
	attempts, err := service.ActionAttempts(ctx, tenantID, execution.ID, 10)
	if err != nil || len(attempts) != 1 || attempts[0].Status != "SUCCEEDED" || attempts[0].VerificationStatus != "VERIFIED" || executor.total() != 1 {
		t.Fatalf("exactly-once action evidence: attempts=%+v calls=%d err=%v", attempts, executor.total(), err)
	}
	completed, err := service.Execution(ctx, tenantID, execution.ID)
	if err != nil || completed.Status != core.SOARExecutionSucceeded {
		t.Fatalf("workflow did not complete: %+v err=%v", completed, err)
	}
	audit, err := repository.ListAudit(ctx, tenantID, 20)
	if err != nil || len(audit) == 0 || audit[0].Action != "soar.approval.approve" || audit[0].Metadata["new_status"] != string(core.ApprovalStatusApproved) {
		t.Fatalf("approval audit evidence: %+v err=%v", audit, err)
	}
	chainValid, err := repository.VerifyAudit(ctx, tenantID)
	if err != nil {
		t.Fatalf("verify approval audit chain: %v", err)
	}
	if !chainValid {
		t.Fatal("expected approval audit chain to be valid")
	}
}

func TestPostgresSOARApprovalRejectStopsProtectedAction(t *testing.T) {
	repository, service, tenantID, execution, approval := createApprovalRuntime(t, 1)
	ctx := context.Background()
	rejected, err := service.DecideApproval(ctx, tenantID, approval.ID, "soc-manager", approvalRequest(core.ApprovalDecisionReject, "Endpoint ownership is not verified", approval.Version, "req-reject"))
	if err != nil || rejected.Status != core.ApprovalStatusRejected || rejected.Version != 2 {
		t.Fatalf("reject: %+v err=%v", rejected, err)
	}
	executor := &countingApprovalExecutor{}
	worker := soar.NewWorker(repository, nil, executor, soar.WorkerConfig{ID: "rejected-worker", TenantID: tenantID, Lease: time.Second}, nil)
	if worked, err := worker.ProcessOne(ctx); err != nil || worked {
		t.Fatalf("rejected action became claimable: worked=%v err=%v", worked, err)
	}
	attempts, err := service.ActionAttempts(ctx, tenantID, execution.ID, 10)
	if err != nil || len(attempts) != 0 || executor.total() != 0 {
		t.Fatalf("protected action ran after reject: attempts=%+v calls=%d err=%v", attempts, executor.total(), err)
	}
	failed, err := service.Execution(ctx, tenantID, execution.ID)
	if err != nil || failed.Status != core.SOARExecutionFailed {
		t.Fatalf("reject branch did not stop workflow: %+v err=%v", failed, err)
	}
}

func TestPostgresSOARApprovalConcurrentDecisionsUseOptimisticLock(t *testing.T) {
	_, service, tenantID, _, approval := createApprovalRuntime(t, 1)
	ctx := context.Background()
	type result struct {
		approval core.SOARApproval
		err      error
	}
	results := make(chan result, 2)
	var start sync.WaitGroup
	start.Add(1)
	for index, decision := range []core.ApprovalDecision{core.ApprovalDecisionApprove, core.ApprovalDecisionReject} {
		go func(index int, decision core.ApprovalDecision) {
			start.Wait()
			item, err := service.DecideApproval(ctx, tenantID, approval.ID, []string{"soc-manager", "tenant-admin"}[index], approvalRequest(decision, "Concurrent independent decision", approval.Version, "req-concurrent"))
			results <- result{item, err}
		}(index, decision)
	}
	start.Done()
	successes, conflicts := 0, 0
	for range 2 {
		item := <-results
		if item.err == nil {
			successes++
		} else if errors.Is(item.err, soar.ErrApprovalVersionConflict) {
			conflicts++
		} else {
			t.Fatalf("unexpected concurrent result: %v", item.err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("concurrency gate: successes=%d conflicts=%d", successes, conflicts)
	}
	final, err := service.Approvals(ctx, tenantID, core.SOARApprovalFilter{ExecutionID: approval.ExecutionID, Limit: 10})
	if err != nil || len(final) != 1 || len(final[0].Decisions) != 1 || final[0].Version != 2 {
		t.Fatalf("concurrent final state: %+v err=%v", final, err)
	}
}

func TestPostgresSOARApprovalTenantExpiryAndAlreadyDecidedGuards(t *testing.T) {
	repository, service, tenantID, _, approval := createApprovalRuntime(t, 1)
	ctx := context.Background()
	if _, err := service.DecideApproval(ctx, "other-tenant", approval.ID, "soc-manager", approvalRequest(core.ApprovalDecisionApprove, "Reviewed", approval.Version, "req-wrong-tenant")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant approval was not hidden: %v", err)
	}
	if _, err := repository.pool.Exec(ctx, `UPDATE soar_approvals SET expires_at=$3 WHERE tenant_id=$1 AND approval_id=$2`, tenantID, approval.ID, time.Now().UTC().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := service.DecideApproval(ctx, tenantID, approval.ID, "soc-manager", approvalRequest(core.ApprovalDecisionApprove, "Reviewed", approval.Version, "req-expired")); !errors.Is(err, soar.ErrInvalidState) {
		t.Fatalf("expired approval accepted: %v", err)
	}
	items, err := service.Approvals(ctx, tenantID, core.SOARApprovalFilter{ExecutionID: approval.ExecutionID, Limit: 10})
	if err != nil || items[0].Status != core.ApprovalStatusExpired || items[0].Version != 2 {
		t.Fatalf("expired state not persisted: %+v err=%v", items, err)
	}
}
