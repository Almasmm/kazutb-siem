package store_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/store"
	"github.com/kcsp/platform/internal/ueba"
)

func TestPostgresUEBABaselineFeedbackAndTenantIsolation(t *testing.T) {
	databaseURL := os.Getenv("KCSP_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("KCSP_TEST_DATABASE_URL is not configured")
	}
	ctx := context.Background()
	repository, err := store.OpenPostgres(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	tenantID := core.NewID("tenant-ueba")
	if err := repository.EnsureTenant(ctx, tenantID, "UEBA Integration Tenant"); err != nil {
		repository.Close()
		t.Fatal(err)
	}
	if err := repository.ResetTenant(ctx, tenantID); err != nil {
		repository.Close()
		t.Fatal(err)
	}
	started := time.Now().UTC().Add(-4 * time.Hour).Truncate(time.Minute)
	for index := 0; index < 50; index++ {
		event := integrationUEBAEvent(tenantID, "training-"+time.Duration(index).String(), started.Add(time.Duration(index)*time.Minute), "workstation-01", "10.0.0.10", "powershell.exe", "intranet.local")
		if _, _, err := repository.PutEvent(ctx, event); err != nil {
			repository.Close()
			t.Fatal(err)
		}
		anomaly, err := repository.ObserveUEBAEvent(ctx, event)
		if err != nil || anomaly != nil {
			repository.Close()
			t.Fatalf("stable training observation failed: anomaly=%+v err=%v", anomaly, err)
		}
	}
	novel := integrationUEBAEvent(tenantID, "novel-event", time.Now().UTC(), "visitor-laptop", "198.51.100.72", "rare-tool.exe", "unseen.example")
	novel.Metadata = map[string]interface{}{"src_country": "ZZ", "src_asn": "AS64550"}
	if _, _, err := repository.PutEvent(ctx, novel); err != nil {
		repository.Close()
		t.Fatal(err)
	}
	anomaly, err := repository.ObserveUEBAEvent(ctx, novel)
	if err != nil || anomaly == nil {
		repository.Close()
		t.Fatalf("novel observation did not persist anomaly: %+v err=%v", anomaly, err)
	}
	if anomaly.RiskScore > 75 || anomaly.Severity == core.SeverityCritical || len(anomaly.Features) == 0 {
		repository.Close()
		t.Fatalf("invalid persisted anomaly: %+v", anomaly)
	}
	service := ueba.NewService(repository)
	items, err := service.Anomalies(ctx, tenantID, core.UEBAAnomalyFilter{EntityType: "user", EntityID: "alice", Limit: 10})
	if err != nil || len(items) != 1 {
		repository.Close()
		t.Fatalf("list UEBA anomalies: %+v err=%v", items, err)
	}
	updated, err := service.Feedback(ctx, tenantID, anomaly.ID, "soc-l2", ueba.FeedbackRequest{
		Status: core.UEBAAnomalyFalsePositive, Reason: "Approved onboarding activity", Version: anomaly.Version,
	})
	if err != nil || updated.Status != core.UEBAAnomalyFalsePositive || updated.Version != anomaly.Version+1 {
		repository.Close()
		t.Fatalf("update UEBA feedback: %+v err=%v", updated, err)
	}
	if _, err := service.Feedback(ctx, tenantID, anomaly.ID, "soc-l2", ueba.FeedbackRequest{
		Status: core.UEBAAnomalyConfirmed, Reason: "stale decision", Version: anomaly.Version,
	}); !errors.Is(err, store.ErrVersionConflict) {
		repository.Close()
		t.Fatalf("stale UEBA feedback was accepted: %v", err)
	}
	if _, err := service.Baseline(ctx, "another-tenant", "user", "alice"); !errors.Is(err, store.ErrNotFound) {
		repository.Close()
		t.Fatalf("cross-tenant UEBA profile lookup was accepted: %v", err)
	}
	repository.Close()
	reopened, err := store.OpenPostgres(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	baseline, err := reopened.GetUEBABaseline(ctx, tenantID, "user", "alice")
	if err != nil || baseline.ObservationCount < 51 || baseline.ModelVersion == "" {
		t.Fatalf("UEBA baseline did not survive restart: %+v err=%v", baseline, err)
	}
}

func integrationUEBAEvent(tenantID, id string, at time.Time, device, ip, process, destination string) core.CanonicalEvent {
	return core.CanonicalEvent{
		ID: id, TenantID: tenantID, EventTime: at, IngestTime: at, Category: "process_activity",
		ActivityName: "Process created", Source: core.EventSource{Type: "sysmon"},
		User:        core.UserRef{ID: "alice", Name: "Alice"},
		Device:      core.DeviceRef{ID: device, Hostname: device, IP: ip, Department: "Engineering"},
		SrcEndpoint: core.EndpointRef{IP: ip}, DstEndpoint: core.EndpointRef{Hostname: destination},
		Process: core.ProcessRef{Name: process},
	}
}
