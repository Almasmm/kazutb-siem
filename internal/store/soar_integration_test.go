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
	defer repository.Close()
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
