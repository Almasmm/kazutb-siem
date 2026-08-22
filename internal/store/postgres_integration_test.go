package store_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/pipeline"
	"github.com/kcsp/platform/internal/soc"
	"github.com/kcsp/platform/internal/store"
)

func TestPostgresPersistsDetectionIncidentAndAuditAcrossRestart(t *testing.T) {
	databaseURL := os.Getenv("KCSP_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("KCSP_TEST_DATABASE_URL is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tenantID := "integration-" + core.NewID("tenant")

	repository, err := store.OpenPostgres(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.EnsureTenant(ctx, tenantID, "KCSP Integration Tenant"); err != nil {
		repository.Close()
		t.Fatal(err)
	}
	if err := repository.ResetTenant(ctx, tenantID); err != nil {
		repository.Close()
		t.Fatal(err)
	}
	engine, err := pipeline.New(ctx, repository)
	if err != nil {
		repository.Close()
		t.Fatal(err)
	}
	result, err := engine.Ingest(ctx, tenantID, core.CanonicalEvent{
		ID: "sysmon-persistence-1", EventTime: time.Now().UTC().Add(-time.Minute),
		Category: "process_activity", ActivityName: "Process created",
		Source:  core.EventSource{Vendor: "Microsoft", Product: "Sysmon", Type: "endpoint"},
		User:    core.UserRef{Name: "KCSP\\admin", IsPrivileged: true},
		Device:  core.DeviceRef{Hostname: "dc-integration", Criticality: 5},
		Process: core.ProcessRef{Name: "powershell.exe", CommandLine: "powershell.exe -EncodedCommand SQBFAFgA"},
		Raw:     core.RawRef{Message: `{"EventID":1,"Image":"powershell.exe","CommandLine":"-EncodedCommand SQBFAFgA"}`},
	})
	if err != nil {
		repository.Close()
		t.Fatal(err)
	}
	if len(result.Findings) != 1 || len(result.Alerts) != 1 {
		repository.Close()
		t.Fatalf("expected one finding and alert, got %d and %d", len(result.Findings), len(result.Alerts))
	}
	service := soc.New(repository)
	incident, duplicate, err := service.CreateIncident(ctx, tenantID, "integration-analyst", soc.CreateIncidentInput{
		Title: "Persistent Sysmon investigation", AlertIDs: []string{result.Alerts[0].ID}, RequestID: "integration-request",
	})
	if err != nil || duplicate {
		repository.Close()
		t.Fatalf("create incident: duplicate=%v err=%v", duplicate, err)
	}
	repository.Close()

	reopened, err := store.OpenPostgres(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	t.Cleanup(func() { _ = reopened.ResetTenant(context.Background(), tenantID) })
	storedEvent, err := reopened.GetEvent(ctx, tenantID, result.Event.ID)
	if err != nil || storedEvent.Raw.Hash == "" || storedEvent.EventTime.IsZero() {
		t.Fatalf("event did not survive repository restart: event=%+v err=%v", storedEvent, err)
	}
	storedAlert, err := reopened.GetAlert(ctx, tenantID, result.Alerts[0].ID)
	if err != nil || storedAlert.Status != "IN_PROGRESS" {
		t.Fatalf("alert did not survive repository restart: alert=%+v err=%v", storedAlert, err)
	}
	storedIncident, err := reopened.GetIncident(ctx, tenantID, incident.ID)
	if err != nil || storedIncident.Title != incident.Title {
		t.Fatalf("incident did not survive repository restart: incident=%+v err=%v", storedIncident, err)
	}
	valid, err := reopened.VerifyAudit(ctx, tenantID)
	if err != nil || !valid {
		t.Fatalf("durable audit chain invalid: valid=%v err=%v", valid, err)
	}
	restartedEngine, err := pipeline.New(ctx, reopened)
	if err != nil {
		t.Fatal(err)
	}
	duplicateResult, err := restartedEngine.Ingest(ctx, tenantID, result.Event)
	if err != nil || !duplicateResult.Duplicate {
		t.Fatalf("event idempotency failed after restart: duplicate=%v err=%v", duplicateResult.Duplicate, err)
	}
}
