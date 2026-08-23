package mitre

import (
	"context"
	"testing"
	"time"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/store"
)

type coverageRepository struct {
	rules      []core.DetectionRule
	collectors []core.Collector
	incidents  []core.Incident
}

func (r coverageRepository) ListRules(context.Context) ([]core.DetectionRule, error) {
	return r.rules, nil
}
func (r coverageRepository) PublishedDetectionContent(context.Context, string) ([]core.DetectionContent, error) {
	return []core.DetectionContent{}, nil
}
func (r coverageRepository) ListCollectors(context.Context, string) ([]core.Collector, error) {
	return r.collectors, nil
}
func (r coverageRepository) ListIncidents(context.Context, string, store.IncidentFilter) ([]core.Incident, error) {
	return r.incidents, nil
}

func TestCoverageCombinesRulesCollectorsAndIncidentRisk(t *testing.T) {
	now := time.Now().UTC()
	repository := coverageRepository{
		rules:      []core.DetectionRule{{ID: "rule-ps", Title: "PowerShell", Version: "1", State: "PUBLISHED", MITRE: []string{"T1059.001"}, RequiredDataSources: []string{"Sysmon Event ID 1"}, Severity: core.SeverityHigh, UpdatedAt: now}},
		collectors: []core.Collector{{ID: "collector-sysmon", TenantID: "tenant-a", Name: "Windows Fleet", Type: "windows", State: "ACTIVE", Capabilities: []string{"sysmon"}}},
		incidents:  []core.Incident{{ID: "incident-1", TenantID: "tenant-a", Title: "PowerShell incident", Status: "TRIAGE", Severity: core.SeverityHigh, MITRE: []string{"T1059.001"}, RiskScore: 82, CreatedAt: now, UpdatedAt: now}},
	}
	report, err := NewService(repository).Coverage(context.Background(), "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	var powerShell *core.MITRETechniqueCoverage
	for index := range report.Techniques {
		if report.Techniques[index].TechniqueID == "T1059.001" {
			powerShell = &report.Techniques[index]
		}
	}
	if powerShell == nil || powerShell.Status != StatusCovered || powerShell.IncidentCount != 1 || powerShell.MaximumRisk != 82 {
		t.Fatalf("unexpected PowerShell coverage: %#v", powerShell)
	}
	if report.PublishedRules != 1 || report.ActiveCollectors != 1 || report.CoverageGaps == 0 {
		t.Fatalf("unexpected report totals: %#v", report)
	}
}
