package threatintel

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/kcsp/platform/internal/core"
)

func TestParseSTIXBundleReportsUnsupportedObjectsWithoutSilentImport(t *testing.T) {
	payload := []byte(`{
		"type":"bundle",
		"id":"bundle--00000000-0000-4000-8000-000000000001",
		"objects":[
			{"type":"identity","spec_version":"2.1","id":"identity--00000000-0000-4000-8000-000000000002"},
			{"type":"indicator","spec_version":"2.1","id":"indicator--00000000-0000-4000-8000-000000000003",
			 "created":"2026-01-01T00:00:00Z","modified":"2026-01-01T00:00:00Z",
			 "valid_from":"2026-01-01T00:00:00Z","pattern_type":"stix","pattern_version":"2.1",
			 "pattern":"[domain-name:value = 'Evil.Example.']","indicator_types":["malicious-activity"],"confidence":91},
			{"type":"indicator","spec_version":"2.1","id":"indicator--00000000-0000-4000-8000-000000000004",
			 "valid_from":"2026-01-01T00:00:00Z","pattern_type":"stix","pattern":"[network-traffic:dst_port > 22]"}
		]
	}`)
	parsed, report, err := ParseSTIXBundle(payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed) != 1 || report.Skipped != 1 || report.RejectedCount != 1 {
		t.Fatalf("unexpected import report: parsed=%d report=%+v", len(parsed), report)
	}
	if parsed[0].Draft.Type != core.ThreatIndicatorDomain || parsed[0].Draft.Value != "Evil.Example." ||
		parsed[0].Draft.Reputation != "MALICIOUS" {
		t.Fatalf("unexpected parsed indicator: %+v", parsed[0])
	}
}

func TestSTIXExportIsStableAndRoundTripsSupportedPattern(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	indicator := core.ThreatIndicator{
		ID: "ioc-1", TenantID: "tenant-a", FeedID: "feed-a", Type: core.ThreatIndicatorURL,
		NormalizedValue: "https://evil.example/a?x=1", Source: "CSIRT", Confidence: 88,
		Reputation: "MALICIOUS", ValidFrom: now, CreatedAt: now, UpdatedAt: now,
	}
	bundle := BuildSTIXBundle("tenant-a", []core.ThreatIndicator{indicator})
	if bundle.Type != "bundle" || len(bundle.Objects) != 1 || !stixIndicatorID.MatchString(bundle.Objects[0].ID) {
		t.Fatalf("invalid STIX export: %+v", bundle)
	}
	kind, value, err := ParseSTIXPattern(bundle.Objects[0].Pattern)
	if err != nil || kind != core.ThreatIndicatorURL || value != indicator.NormalizedValue {
		t.Fatalf("round trip failed: kind=%s value=%s err=%v", kind, value, err)
	}
	if _, err := json.Marshal(bundle); err != nil {
		t.Fatalf("marshal STIX bundle: %v", err)
	}
}

func TestRetrosearchExpressionUsesOnlyWhitelistedExactFields(t *testing.T) {
	expression, err := RetrosearchExpression(core.ThreatIndicator{
		Type: core.ThreatIndicatorDomain, NormalizedValue: "evil.example",
	})
	if err != nil || len(expression.Any) != 5 {
		t.Fatalf("unexpected expression: %+v err=%v", expression, err)
	}
	for _, branch := range expression.Any {
		if branch.Predicate == nil || branch.Predicate.Comparator != "eq" || branch.Predicate.Value != "evil.example" {
			t.Fatalf("unsafe retrosearch predicate: %+v", branch)
		}
	}
}
