package store_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/store"
)

func TestPostgresCollectorRegistryPersistsBindingHeartbeatAndRevocation(t *testing.T) {
	databaseURL := os.Getenv("KCSP_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("KCSP_TEST_DATABASE_URL is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tenantID := "collector-" + core.NewID("tenant")
	repository, err := store.OpenPostgres(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.EnsureTenant(ctx, tenantID, "Collector Registry Test"); err != nil {
		repository.Close()
		t.Fatal(err)
	}
	if err := repository.ResetTenant(ctx, tenantID); err != nil {
		repository.Close()
		t.Fatal(err)
	}
	registered, err := repository.RegisterCollector(ctx, core.Collector{
		ID: "windows-dc01", TenantID: tenantID, Name: "Domain Controller 01", Type: "windows-agent",
		AuthSubject: "oidc-service-subject-dc01", Capabilities: []string{"Sysmon", "sysmon", "event-log"},
	})
	if err != nil {
		repository.Close()
		t.Fatal(err)
	}
	if registered.State != "ACTIVE" || registered.Health != "NEVER_SEEN" || len(registered.Capabilities) != 2 {
		repository.Close()
		t.Fatalf("unexpected registration: %+v", registered)
	}
	if _, err := repository.RegisterCollector(ctx, core.Collector{
		ID: "duplicate", TenantID: tenantID, Name: "Duplicate", Type: "windows-agent", AuthSubject: registered.AuthSubject,
	}); !errors.Is(err, store.ErrAlreadyExists) {
		repository.Close()
		t.Fatalf("expected duplicate binding rejection, got %v", err)
	}
	repository.Close()

	reopened, err := store.OpenPostgres(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_ = reopened.ResetTenant(cleanupCtx, tenantID)
	})
	persisted, err := reopened.CollectorBySubject(ctx, tenantID, registered.AuthSubject)
	if err != nil || persisted.ID != registered.ID {
		t.Fatalf("collector binding did not persist: collector=%+v err=%v", persisted, err)
	}
	heartbeat, err := reopened.HeartbeatCollector(ctx, tenantID, registered.AuthSubject, core.CollectorHeartbeat{
		Version: "0.2.0", Metadata: map[string]interface{}{"queue_depth": float64(0)},
	}, "10.10.10.5")
	if err != nil || heartbeat.Health != "ONLINE" || heartbeat.Version != "0.2.0" || heartbeat.LastSeenAt == nil {
		t.Fatalf("heartbeat failed: collector=%+v err=%v", heartbeat, err)
	}
	items, err := reopened.ListCollectors(ctx, tenantID)
	if err != nil || len(items) != 1 || items[0].ObservedIP != "10.10.10.5" {
		t.Fatalf("collector inventory failed: items=%+v err=%v", items, err)
	}
	revoked, err := reopened.SetCollectorState(ctx, tenantID, registered.ID, "REVOKED")
	if err != nil || revoked.Health != "REVOKED" {
		t.Fatalf("collector revocation failed: collector=%+v err=%v", revoked, err)
	}
	if _, err := reopened.HeartbeatCollector(ctx, tenantID, registered.AuthSubject, core.CollectorHeartbeat{Version: "0.2.1"}, "10.10.10.5"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("revoked collector heartbeat was accepted: %v", err)
	}
}
