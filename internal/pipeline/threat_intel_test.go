package pipeline

import (
	"context"
	"testing"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/store"
)

type threatIntelTestRepository struct {
	*store.MemoryRepository
}

func (r *threatIntelTestRepository) MatchThreatIntelEvent(_ context.Context, event core.CanonicalEvent) ([]core.ThreatIntelMatch, error) {
	if event.SrcEndpoint.IP != "203.0.113.7" {
		return nil, nil
	}
	return []core.ThreatIntelMatch{{
		ID: "match-1", TenantID: event.TenantID, IndicatorID: "ioc-1", IndicatorVersion: 3,
		FeedID: "feed-1", EventID: event.ID, Type: core.ThreatIndicatorIPv4, Value: "203.0.113.7",
		MatchedField: "src_endpoint.ip", MatchedValue: "203.0.113.7", Confidence: 90,
		Reputation: "MALICIOUS",
	}, {
		ID: "match-2", TenantID: event.TenantID, IndicatorID: "ioc-1", IndicatorVersion: 3,
		FeedID: "feed-1", EventID: event.ID, Type: core.ThreatIndicatorIPv4, Value: "203.0.113.7",
		MatchedField: "metadata.network.source_ip", MatchedValue: "203.0.113.7", Confidence: 90,
		Reputation: "MALICIOUS",
	}}, nil
}

func TestThreatIntelMatchUsesExistingFindingRiskAlertAuditPath(t *testing.T) {
	memory := store.NewMemory()
	repository := &threatIntelTestRepository{MemoryRepository: store.WrapMemory(memory)}
	engine, err := New(context.Background(), repository)
	if err != nil {
		t.Fatal(err)
	}
	result, err := engine.Ingest(context.Background(), "tenant-a", core.CanonicalEvent{
		ID: "event-ti", Category: "network_activity",
		Source:      core.EventSource{Vendor: "Test", Product: "Firewall", Type: "network"},
		SrcEndpoint: core.EndpointRef{IP: "203.0.113.7"},
		Device:      core.DeviceRef{Hostname: "student-laptop"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 1 || len(result.Alerts) != 1 {
		t.Fatalf("expected one finding and alert: %+v", result)
	}
	finding := result.Findings[0]
	if finding.Rule.ID != ThreatIntelRuleID || finding.Confidence != 90 ||
		!hasFactor(finding.RiskBreakdown, "threat_intelligence") {
		t.Fatalf("unexpected threat intelligence finding: %+v", finding)
	}
	if len(finding.MatchedFields) != 2 {
		t.Fatalf("field-level IOC matches were not aggregated: %+v", finding.MatchedFields)
	}
	if result.Alerts[0].RiskScore != finding.RiskScore {
		t.Fatalf("alert did not preserve explainable risk: %+v", result.Alerts[0])
	}
	if !memory.VerifyAudit("tenant-a") {
		t.Fatal("threat intelligence alert broke the audit chain")
	}
}
