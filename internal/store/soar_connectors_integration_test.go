package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/soar"
	"github.com/kcsp/platform/internal/store"
)

func TestPostgresSOARConnectorLifecycleAndDurableTestQueue(t *testing.T) {
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
	tenantID := "soar-connector-" + core.NewID("tenant")
	if err := repository.EnsureTenant(ctx, tenantID, "SOAR Connector Test"); err != nil {
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
	connector, err := service.CreateConnector(ctx, tenantID, "soar-engineer", soar.ConnectorDraft{
		Name: "University ITSM webhook", Kind: "WEBHOOK", Endpoint: "https://itsm.example.edu/kcsp",
		AuthType: "BEARER", AllowedActions: []string{"kcsp.ticket.create"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if connector.State != core.SOARConnectorCredentialsNeeded ||
		connector.HealthStatus != core.SOARConnectorHealthCredentials || connector.SecretRef != "" {
		t.Fatalf("unexpected credentials-required connector: %+v", connector)
	}
	requestID := "connector-test-" + core.NewID("request")
	first, created, err := service.QueueConnectorTest(ctx, tenantID, connector.ID, "soar-engineer", requestID)
	if err != nil || !created {
		t.Fatalf("queue connector test: created=%v test=%+v err=%v", created, first, err)
	}
	second, created, err := service.QueueConnectorTest(ctx, tenantID, connector.ID, "soar-engineer", requestID)
	if err != nil || created || second.ID != first.ID {
		t.Fatalf("connector test idempotency failed: created=%v test=%+v err=%v", created, second, err)
	}
	item, found, err := repository.ClaimSOARConnectorTest(ctx, "connector-worker", tenantID, time.Minute)
	if err != nil || !found || item.Test.ID != first.ID || item.Connector.ID != connector.ID {
		t.Fatalf("claim connector test: found=%v item=%+v err=%v", found, item, err)
	}
	finished, err := repository.FinishSOARConnectorTest(ctx, tenantID, first.ID, "connector-worker",
		core.SOARConnectorTestCredentials, "CREDENTIALS_REQUIRED", "connector has no secret binding", 0, 0)
	if err != nil || finished.Status != core.SOARConnectorTestCredentials {
		t.Fatalf("finish connector test: %+v err=%v", finished, err)
	}
	current, err := service.Connector(ctx, tenantID, connector.ID)
	if err != nil || current.State != core.SOARConnectorCredentialsNeeded ||
		current.HealthStatus != core.SOARConnectorHealthCredentials || current.Version != connector.Version+1 {
		t.Fatalf("connector health was not reconciled: %+v err=%v", current, err)
	}
	secretRef := "env://KCSP_CONNECTOR_SECRET_ITSM"
	updated, err := service.UpdateConnector(ctx, tenantID, connector.ID, "soar-engineer", soar.ConnectorPatch{
		Version: current.Version, SecretRef: &secretRef,
	})
	if err != nil || updated.SecretRef != secretRef || updated.State != core.SOARConnectorCredentialsNeeded {
		t.Fatalf("update connector secret binding: %+v err=%v", updated, err)
	}
	if _, err := service.UpdateConnector(ctx, tenantID, connector.ID, "soar-engineer", soar.ConnectorPatch{
		Version: current.Version, Name: "Stale update",
	}); !errors.Is(err, store.ErrVersionConflict) {
		t.Fatalf("stale connector update was accepted: %v", err)
	}
	if _, err := service.Connector(ctx, "another-tenant", connector.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("cross-tenant connector lookup was accepted: %v", err)
	}
}

func TestPostgresSOARWebhookExecutesA2OnceAndEnforcesRateLimit(t *testing.T) {
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
	tenantID := "soar-webhook-" + core.NewID("tenant")
	if err := repository.EnsureTenant(ctx, tenantID, "SOAR Webhook Test"); err != nil {
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
	var deliveries atomic.Int32
	webhook := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodHead:
			w.WriteHeader(http.StatusNoContent)
		case http.MethodPost:
			if r.Header.Get("Idempotency-Key") == "" || r.Header.Get("Content-Type") != "application/json" {
				http.Error(w, "missing contract headers", http.StatusBadRequest)
				return
			}
			var payload map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil ||
				payload["action_type"] != "kcsp.notification.send" {
				http.Error(w, "invalid action contract", http.StatusBadRequest)
				return
			}
			deliveries.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"message_id": "msg-1", "verified": true,
			})
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}))
	defer webhook.Close()
	service := soar.NewService(repository, nil)
	connector, err := service.CreateConnector(ctx, tenantID, "soar-engineer", soar.ConnectorDraft{
		Name: "Verified SOC notification", Kind: "WEBHOOK", Endpoint: webhook.URL,
		AuthType: "NONE", AllowedActions: []string{"kcsp.notification.send"},
		Settings:           map[string]interface{}{"health_method": "HEAD", "expected_status": 204},
		RateLimitPerMinute: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.QueueConnectorTest(ctx, tenantID, connector.ID, "soar-engineer",
		"health-"+core.NewID("request")); err != nil {
		t.Fatal(err)
	}
	executor := soar.NewManagedConnectorExecutor(repository, nil, webhook.Client())
	worker := soar.NewWorker(repository, nil, executor, soar.WorkerConfig{
		ID: "webhook-worker", TenantID: tenantID, PollInterval: time.Millisecond, Lease: time.Minute,
	}, nil)
	processOne := func(message string) {
		t.Helper()
		deadline := time.Now().Add(time.Second)
		for {
			worked, processErr := worker.ProcessOne(ctx)
			if processErr != nil {
				t.Fatalf("%s: %v", message, processErr)
			}
			if worked {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s: worker did not claim the ready job", message)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	processOne("process connector health test")
	healthy, err := service.Connector(ctx, tenantID, connector.ID)
	if err != nil || healthy.State != core.SOARConnectorReady ||
		healthy.HealthStatus != core.SOARConnectorHealthHealthy {
		t.Fatalf("connector did not become ready: %+v err=%v", healthy, err)
	}
	spec := core.SOARPlaybookSpec{
		SchemaVersion: "1.0", Trigger: core.SOARTrigger{Type: "MANUAL"},
		Nodes: []core.SOARNode{{
			ID: "notify", Type: core.SOARNodeAction, Name: "Notify SOC", TimeoutSeconds: 5,
			Config: map[string]interface{}{
				"action_type": "kcsp.notification.send", "mode": "LIVE", "connector_id": connector.ID,
				"parameters": map[string]interface{}{"channel": "soc", "message": "Review incident"},
			},
		}},
	}
	playbook, err := service.CreatePlaybook(ctx, tenantID, "soar-engineer",
		soar.PlaybookDraft{Name: "Verified notification", Spec: spec})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.PublishVersion(ctx, tenantID, playbook.Playbook.ID, 1, "soar-engineer"); err != nil {
		t.Fatal(err)
	}
	start := func(requestID string) core.SOARExecution {
		execution, created, err := service.StartExecution(ctx, tenantID, "soc-l2", soar.ExecutionRequest{
			PlaybookID: playbook.Playbook.ID, RequestID: requestID, TriggerType: "MANUAL",
		})
		if err != nil || !created {
			t.Fatalf("start webhook execution: created=%v execution=%+v err=%v", created, execution, err)
		}
		return execution
	}
	first := start("webhook-first-" + core.NewID("request"))
	processOne("execute webhook action")
	first, err = service.Execution(ctx, tenantID, first.ID)
	if err != nil || first.Status != core.SOARExecutionSucceeded || deliveries.Load() != 1 {
		t.Fatalf("webhook action was not completed exactly once: %+v deliveries=%d err=%v",
			first, deliveries.Load(), err)
	}
	attempts, err := service.ActionAttempts(ctx, tenantID, first.ID, 10)
	if err != nil || len(attempts) != 1 || attempts[0].VerificationStatus != "VERIFIED" ||
		attempts[0].Result["message_id"] != "msg-1" {
		t.Fatalf("webhook action ledger is incomplete: %+v err=%v", attempts, err)
	}
	second := start("webhook-second-" + core.NewID("request"))
	processOne("process rate-limited webhook action")
	second, err = service.Execution(ctx, tenantID, second.ID)
	if err != nil || second.Status != core.SOARExecutionFailed || deliveries.Load() != 1 {
		t.Fatalf("rate limit did not prevent a second delivery: %+v deliveries=%d err=%v",
			second, deliveries.Load(), err)
	}
}
