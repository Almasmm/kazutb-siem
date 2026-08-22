package pipeline

import (
	"context"
	"testing"
	"time"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/store"
)

func TestSuspiciousPowerShellCreatesExplainableFindingAndAlert(t *testing.T) {
	memory := store.NewMemory()
	engine := New(memory)
	result, err := engine.Ingest(context.Background(), "tenant-a", core.CanonicalEvent{
		ID: "evt-1", EventTime: time.Now().UTC(), Category: "process_activity", ActivityName: "Process created",
		Source:  core.EventSource{Vendor: "Microsoft", Product: "Sysmon", Type: "endpoint"},
		User:    core.UserRef{Name: "ACME\\admin", IsPrivileged: true},
		Device:  core.DeviceRef{Hostname: "dc-01", Criticality: 5},
		Process: core.ProcessRef{Name: "powershell.exe", CommandLine: "powershell.exe -EncodedCommand SQBFAFgA"},
	})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if len(result.Findings) != 1 || len(result.Alerts) != 1 {
		t.Fatalf("expected one finding and alert, got %d and %d", len(result.Findings), len(result.Alerts))
	}
	finding := result.Findings[0]
	if finding.Rule.ID != PowerShellRuleID {
		t.Fatalf("unexpected rule: %s", finding.Rule.ID)
	}
	if finding.RiskScore != 100 || finding.Severity != core.SeverityCritical {
		t.Fatalf("unexpected risk result: score=%d severity=%s", finding.RiskScore, finding.Severity)
	}
	for _, required := range []string{"base_severity", "rule_confidence", "encoded_command", "critical_asset", "privileged_user"} {
		if !hasFactor(finding.RiskBreakdown, required) {
			t.Errorf("risk breakdown lacks %s", required)
		}
	}
	if !memory.VerifyAudit("tenant-a") {
		t.Fatal("audit chain should verify")
	}
}

func TestBenignPowerShellIsStoredWithoutDetection(t *testing.T) {
	memory := store.NewMemory()
	engine := New(memory)
	result, err := engine.Ingest(context.Background(), "tenant-a", core.CanonicalEvent{
		ID: "evt-benign", Category: "process_activity",
		Source:  core.EventSource{Vendor: "Microsoft", Product: "Sysmon", Type: "endpoint"},
		Process: core.ProcessRef{Name: "powershell.exe", CommandLine: "Get-Service -Name Spooler"},
	})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if len(result.Findings) != 0 || len(result.Alerts) != 0 {
		t.Fatalf("benign event generated detections: %+v", result)
	}
	if _, err := memory.GetEvent("tenant-a", "evt-benign"); err != nil {
		t.Fatalf("event was not stored: %v", err)
	}
}

func TestEventIDIsIdempotentPerTenant(t *testing.T) {
	memory := store.NewMemory()
	engine := New(memory)
	event := core.CanonicalEvent{
		ID: "stable-source-event", Category: "process_activity",
		Source:  core.EventSource{Vendor: "Microsoft", Product: "Sysmon", Type: "endpoint"},
		Process: core.ProcessRef{Name: "powershell.exe", CommandLine: "Invoke-WebRequest https://example.invalid/a"},
	}
	first, err := engine.Ingest(context.Background(), "tenant-a", event)
	if err != nil {
		t.Fatal(err)
	}
	second, err := engine.Ingest(context.Background(), "tenant-a", event)
	if err != nil {
		t.Fatal(err)
	}
	if first.Duplicate || !second.Duplicate {
		t.Fatalf("unexpected duplicate flags: first=%v second=%v", first.Duplicate, second.Duplicate)
	}
	if got := len(memory.ListEvents("tenant-a", store.EventFilter{})); got != 1 {
		t.Fatalf("expected one event, got %d", got)
	}
	if got := len(memory.ListFindings("tenant-a", "", 100)); got != 1 {
		t.Fatalf("expected one finding, got %d", got)
	}
	if got := len(memory.ListAlerts("tenant-a", store.AlertFilter{})); got != 1 {
		t.Fatalf("expected one alert, got %d", got)
	}
}

func TestAuthenticationThresholdFiresOnFifthFailure(t *testing.T) {
	memory := store.NewMemory()
	engine := New(memory)
	now := time.Now().UTC()
	for i := 0; i < 5; i++ {
		result, err := engine.Ingest(context.Background(), "tenant-a", core.CanonicalEvent{
			ID: "auth-" + string(rune('a'+i)), EventTime: now.Add(time.Duration(i) * time.Second),
			Category: "authentication", Source: core.EventSource{Vendor: "Microsoft", Product: "AD", Type: "identity"},
			User: core.UserRef{Name: "user-" + string(rune('a'+i))}, SrcEndpoint: core.EndpointRef{IP: "203.0.113.10"},
			SecurityResult: core.SecurityResult{Outcome: "failure"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if i < 4 && len(result.Findings) != 0 {
			t.Fatalf("threshold fired at observation %d", i+1)
		}
		if i == 4 {
			if len(result.Findings) != 1 || result.Findings[0].Rule.ID != AuthRuleID {
				t.Fatalf("threshold did not create expected finding: %+v", result.Findings)
			}
		}
	}
}

func TestTenantComesFromAuthenticatedContextNotPayload(t *testing.T) {
	memory := store.NewMemory()
	engine := New(memory)
	result, err := engine.Ingest(context.Background(), "tenant-a", core.CanonicalEvent{
		ID: "evt-spoof", TenantID: "tenant-b", Category: "network_activity",
		Source: core.EventSource{Vendor: "Test", Product: "Fixture", Type: "network"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Event.TenantID != "tenant-a" {
		t.Fatalf("payload tenant was trusted: %s", result.Event.TenantID)
	}
	if _, err := memory.GetEvent("tenant-b", "evt-spoof"); err == nil {
		t.Fatal("event leaked into payload-selected tenant")
	}
}

func hasFactor(factors []core.RiskFactor, code string) bool {
	for _, factor := range factors {
		if factor.Code == code {
			return true
		}
	}
	return false
}
