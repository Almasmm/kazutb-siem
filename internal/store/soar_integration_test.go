package store_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/soar"
	"github.com/kcsp/platform/internal/store"
)

func TestPostgresSOARLifecycleAndExecutionIdempotency(t *testing.T) {
	databaseURL := os.Getenv("KCSP_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("KCSP_TEST_DATABASE_URL is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	repository, err := store.OpenPostgres(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(repository.Close)
	tenantID := "soar-" + core.NewID("tenant")
	if err := repository.EnsureTenant(ctx, tenantID, "SOAR Test"); err != nil {
		t.Fatal(err)
	}
	if err := repository.ResetTenant(ctx, tenantID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_ = repository.ResetTenant(cleanupCtx, tenantID)
	})
	service := soar.NewService(repository, nil)
	spec := core.SOARPlaybookSpec{
		SchemaVersion: "1.0", Trigger: core.SOARTrigger{Type: "MANUAL"},
		Nodes: []core.SOARNode{
			{ID: "enrich", Type: core.SOARNodeAction, Name: "Threat intelligence enrichment",
				Config: map[string]interface{}{"action_type": "kcsp.enrich.threat_intel", "mode": "DRY_RUN"}},
			{ID: "task", Type: core.SOARNodeManualTask, Name: "Review enrichment", DependsOn: []string{"enrich"},
				Config: map[string]interface{}{"instructions": "Review the enrichment result"}},
		},
	}
	details, err := service.CreatePlaybook(ctx, tenantID, "soar-engineer", soar.PlaybookDraft{Name: "Manual triage", Spec: spec})
	if err != nil {
		t.Fatal(err)
	}
	if details.Playbook.State != core.SOARPlaybookDraft || !details.Versions[0].Validation.Valid {
		t.Fatalf("unexpected draft: %+v", details)
	}
	published, err := service.PublishVersion(ctx, tenantID, details.Playbook.ID, 1, "soar-engineer")
	if err != nil {
		t.Fatal(err)
	}
	if published.Playbook.State != core.SOARPlaybookPublished || published.Playbook.PublishedVersion != 1 ||
		published.Versions[0].State != core.SOARVersionPublished {
		t.Fatalf("unexpected publish result: %+v", published)
	}
	request := soar.ExecutionRequest{
		PlaybookID: published.Playbook.ID, RequestID: "soar-idempotency-" + core.NewID("request"),
		TriggerType: "MANUAL", Context: map[string]interface{}{"incident_id": "inc-1"},
	}
	first, created, err := service.StartExecution(ctx, tenantID, "soc-l2", request)
	if err != nil || !created {
		t.Fatalf("start execution: created=%v execution=%+v err=%v", created, first, err)
	}
	second, created, err := service.StartExecution(ctx, tenantID, "soc-l2", request)
	if err != nil || created || second.ID != first.ID {
		t.Fatalf("idempotent execution: created=%v execution=%+v err=%v", created, second, err)
	}
	if len(first.Nodes) != 2 || first.Nodes[0].Status != "READY" || first.Nodes[1].Status != "PENDING" {
		t.Fatalf("node snapshots are not durable DAG state: %+v", first.Nodes)
	}
	if _, err := service.Execution(ctx, "another-tenant", first.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("cross-tenant execution lookup was accepted: %v", err)
	}
	invalidSpec := core.SOARPlaybookSpec{
		SchemaVersion: "1.0", Trigger: core.SOARTrigger{Type: "MANUAL"},
		Nodes: []core.SOARNode{{ID: "unsafe", Type: core.SOARNodeTransform, Name: "Unsafe",
			Config: map[string]interface{}{"command": "whoami"}}},
	}
	invalidVersion, err := service.CreateVersion(ctx, tenantID, published.Playbook.ID, "soar-engineer", invalidSpec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.PublishVersion(ctx, tenantID, published.Playbook.ID, invalidVersion.Version, "soar-engineer"); !errors.Is(err, soar.ErrValidationFailed) {
		t.Fatalf("invalid playbook version was published: %v", err)
	}
	current, err := service.Playbook(ctx, tenantID, published.Playbook.ID)
	if err != nil || current.Playbook.PublishedVersion != 1 {
		t.Fatalf("failed publish changed active version: %+v err=%v", current, err)
	}
	if _, err := service.DisablePlaybook(ctx, tenantID, published.Playbook.ID, "soar-engineer"); err != nil {
		t.Fatal(err)
	}
	request.RequestID = "disabled-" + core.NewID("request")
	if _, _, err := service.StartExecution(ctx, tenantID, "soc-l2", request); !errors.Is(err, soar.ErrInvalidState) {
		t.Fatalf("disabled playbook execution was accepted: %v", err)
	}
}

func TestPostgresSOARWorkerApprovalManualResumeAndActionLedger(t *testing.T) {
	databaseURL := os.Getenv("KCSP_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("KCSP_TEST_DATABASE_URL is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	repository, err := store.OpenPostgres(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(repository.Close)
	tenantID := "soar-runtime-" + core.NewID("tenant")
	if err := repository.EnsureTenant(ctx, tenantID, "SOAR Runtime Test"); err != nil {
		t.Fatal(err)
	}
	if err := repository.ResetTenant(ctx, tenantID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_ = repository.ResetTenant(cleanupCtx, tenantID)
	})
	service := soar.NewService(repository, nil)
	spec := core.SOARPlaybookSpec{
		SchemaVersion: "1.0", Trigger: core.SOARTrigger{Type: "MANUAL"},
		Nodes: []core.SOARNode{
			{ID: "enrich", Type: core.SOARNodeAction, Name: "Plan threat intelligence enrichment",
				Config: map[string]interface{}{"action_type": "kcsp.enrich.threat_intel", "mode": "DRY_RUN"}},
			{ID: "approve", Type: core.SOARNodeApproval, Name: "Independent SOC approval",
				DependsOn: []string{"enrich"}, Config: map[string]interface{}{"required_approvals": 2}},
			{ID: "review", Type: core.SOARNodeManualTask, Name: "Record analyst verification",
				DependsOn: []string{"approve"}, Config: map[string]interface{}{"instructions": "Verify the approved response plan"}},
		},
	}
	details, err := service.CreatePlaybook(ctx, tenantID, "soar-engineer",
		soar.PlaybookDraft{Name: "Durable response review", Spec: spec})
	if err != nil {
		t.Fatal(err)
	}
	if !details.Versions[0].Validation.Valid {
		t.Fatalf("runtime test playbook did not validate: %+v", details.Versions[0].Validation)
	}
	published, err := service.PublishVersion(ctx, tenantID, details.Playbook.ID, 1, "soar-engineer")
	if err != nil {
		t.Fatal(err)
	}
	execution, created, err := service.StartExecution(ctx, tenantID, "soc-l2", soar.ExecutionRequest{
		PlaybookID: published.Playbook.ID, RequestID: "soar-runtime-" + core.NewID("request"),
		TriggerType: "MANUAL", Context: map[string]interface{}{"incident_id": "inc-runtime"},
	})
	if err != nil || !created {
		t.Fatalf("start runtime execution: created=%v execution=%+v err=%v", created, execution, err)
	}
	worker := soar.NewWorker(repository, nil, nil, soar.WorkerConfig{
		ID: "integration-worker", TenantID: tenantID, PollInterval: time.Millisecond, Lease: time.Second,
	}, nil)
	if worked, err := worker.ProcessOne(ctx); err != nil || !worked {
		t.Fatalf("process dry-run action: worked=%v err=%v", worked, err)
	}
	attempts, err := service.ActionAttempts(ctx, tenantID, execution.ID, 10)
	if err != nil || len(attempts) != 1 || attempts[0].Status != "SUCCEEDED" ||
		attempts[0].Mode != "DRY_RUN" || attempts[0].VerificationStatus != "DRY_RUN_VERIFIED" {
		t.Fatalf("unexpected durable action ledger: %+v err=%v", attempts, err)
	}
	if worked, err := worker.ProcessOne(ctx); err != nil || !worked {
		t.Fatalf("process approval node: worked=%v err=%v", worked, err)
	}
	approvals, err := service.Approvals(ctx, tenantID, core.SOARApprovalFilter{
		Status: "PENDING", ExecutionID: execution.ID, Limit: 10,
	})
	if err != nil || len(approvals) != 1 || approvals[0].RequiredApprovals != 2 {
		t.Fatalf("unexpected pending approval: %+v err=%v", approvals, err)
	}
	approvalID := approvals[0].ID
	if _, err := service.DecideApproval(ctx, tenantID, approvalID, "soc-l2", soar.ApprovalDecisionRequest{
		Decision: "APPROVE", Reason: "Self approval must fail",
	}); !errors.Is(err, soar.ErrInvalidState) {
		t.Fatalf("execution initiator approved their own action: %v", err)
	}
	if approval, err := service.DecideApproval(ctx, tenantID, approvalID, "soc-manager", soar.ApprovalDecisionRequest{
		Decision: "APPROVE", Reason: "Containment plan reviewed",
	}); err != nil || approval.Status != "PENDING" || len(approval.Decisions) != 1 {
		t.Fatalf("first independent approval failed: %+v err=%v", approval, err)
	}
	if _, err := service.DecideApproval(ctx, tenantID, approvalID, "soc-manager", soar.ApprovalDecisionRequest{
		Decision: "APPROVE", Reason: "Duplicate approval",
	}); !errors.Is(err, store.ErrAlreadyExists) {
		t.Fatalf("duplicate approver was accepted: %v", err)
	}
	if approval, err := service.DecideApproval(ctx, tenantID, approvalID, "tenant-admin", soar.ApprovalDecisionRequest{
		Decision: "APPROVE", Reason: "Second independent review completed",
	}); err != nil || approval.Status != "APPROVED" || len(approval.Decisions) != 2 {
		t.Fatalf("second independent approval failed: %+v err=%v", approval, err)
	}
	if worked, err := worker.ProcessOne(ctx); err != nil || !worked {
		t.Fatalf("process manual task: worked=%v err=%v", worked, err)
	}
	waiting, err := service.Execution(ctx, tenantID, execution.ID)
	if err != nil || waiting.Status != core.SOARExecutionWaitingManual {
		t.Fatalf("execution did not persist manual wait: %+v err=%v", waiting, err)
	}
	completed, err := service.CompleteManualTask(ctx, tenantID, execution.ID, "review", "soc-l2",
		map[string]interface{}{"verified": true, "note": "Dry-run plan verified"})
	if err != nil || completed.Status != core.SOARExecutionSucceeded {
		t.Fatalf("manual resume did not complete execution: %+v err=%v", completed, err)
	}
	for _, node := range completed.Nodes {
		if node.Status != "SUCCEEDED" {
			t.Fatalf("node %s was not durably completed: %+v", node.NodeID, node)
		}
	}
}
