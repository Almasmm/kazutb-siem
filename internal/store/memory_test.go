package store

import (
	"testing"
	"time"

	"github.com/kcsp/platform/internal/core"
)

func TestTenantScopedEventsAndAuditChain(t *testing.T) {
	memory := NewMemory()
	now := time.Now().UTC()
	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		stored, duplicate := memory.PutEvent(core.CanonicalEvent{ID: "same-id", TenantID: tenant, IngestTime: now, Category: "test"})
		if duplicate || stored.TenantID != tenant {
			t.Fatalf("unexpected store result for %s", tenant)
		}
	}
	if got := len(memory.ListEvents("tenant-a", EventFilter{})); got != 1 {
		t.Fatalf("tenant event count=%d", got)
	}
	if _, err := memory.GetEvent("tenant-b", "same-id"); err != nil {
		t.Fatal(err)
	}
	if _, err := memory.GetEvent("tenant-c", "same-id"); err != ErrNotFound {
		t.Fatalf("expected not found, got %v", err)
	}
	first := memory.AppendAudit(core.AuditEntry{TenantID: "tenant-a", Actor: "one", Action: "created", ResourceType: "event", ResourceID: "same-id", Outcome: "success"})
	second := memory.AppendAudit(core.AuditEntry{TenantID: "tenant-a", Actor: "two", Action: "reviewed", ResourceType: "event", ResourceID: "same-id", Outcome: "success"})
	if second.PreviousHash != first.Hash || !memory.VerifyAudit("tenant-a") {
		t.Fatal("audit entries are not correctly chained")
	}
	entries := memory.ListAudit("tenant-a", 10)
	if len(entries) != 2 || entries[0].ID != second.ID {
		t.Fatalf("audit should be returned newest first: %+v", entries)
	}
}

func TestAlertDedupFilteringMutationAndOverview(t *testing.T) {
	memory := NewMemory()
	now := time.Now().UTC()
	base := core.Alert{
		ID: "alert-1", TenantID: "tenant-a", Title: "Rule match", Severity: core.SeverityHigh,
		RiskScore: 70, Status: "NEW", Rule: core.RuleRef{ID: "rule-1", Title: "Rule one"},
		Entity: core.EntitySummary{Type: "user", Name: "alice"}, FindingIDs: []string{"finding-1"}, EventIDs: []string{"event-1"},
		EventCount: 1, FirstSeen: now, LastSeen: now, Version: 1, CreatedAt: now, UpdatedAt: now,
	}
	created, isNew := memory.UpsertAlert(base, "rule-1|user|alice", 15*time.Minute)
	if !isNew || created.ID != "alert-1" {
		t.Fatalf("first alert was not created: %+v", created)
	}
	second := base
	second.ID = "alert-2"
	second.RiskScore = 92
	second.Severity = core.SeverityCritical
	second.FindingIDs = []string{"finding-2"}
	second.EventIDs = []string{"event-2"}
	second.LastSeen = now.Add(time.Minute)
	aggregated, isNew := memory.UpsertAlert(second, "rule-1|user|alice", 15*time.Minute)
	if isNew || aggregated.ID != "alert-1" || aggregated.EventCount != 2 || aggregated.RiskScore != 92 {
		t.Fatalf("unexpected aggregation: %+v", aggregated)
	}
	items := memory.ListAlerts("tenant-a", AlertFilter{Severity: core.SeverityCritical, Query: "alice"})
	if len(items) != 1 {
		t.Fatalf("filtered alert count=%d", len(items))
	}
	mutated, err := memory.MutateAlert("tenant-a", aggregated.ID, aggregated.Version, func(alert *core.Alert) error {
		alert.Status = "ACKNOWLEDGED"
		alert.Assignee = "analyst"
		return nil
	})
	if err != nil || mutated.Status != "ACKNOWLEDGED" {
		t.Fatalf("mutation failed: %+v %v", mutated, err)
	}
	if _, err := memory.MutateAlert("tenant-a", aggregated.ID, 1, func(*core.Alert) error { return nil }); err != ErrVersionConflict {
		t.Fatalf("expected version conflict, got %v", err)
	}
	overview := memory.Overview("tenant-a")
	metrics := overview["metrics"].(map[string]interface{})
	if metrics["open_alerts"].(int) != 1 {
		t.Fatalf("unexpected overview metrics: %+v", metrics)
	}
}
