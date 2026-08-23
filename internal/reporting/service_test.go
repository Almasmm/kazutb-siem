package reporting

import (
	"strings"
	"testing"
	"time"

	"github.com/kcsp/platform/internal/core"
)

func TestOperationalMetricsAndExportsAreDeterministic(t *testing.T) {
	now := time.Now().UTC()
	ack := now.Add(-20 * time.Minute)
	alerts := []core.Alert{{ID: "a1", Status: "CLOSED", Severity: core.SeverityHigh, Disposition: "FALSE_POSITIVE", Rule: core.RuleRef{ID: "rule-1"}, Entity: core.EntitySummary{Name: "host-1"}, FirstSeen: now.Add(-2 * time.Hour), CreatedAt: now.Add(-90 * time.Minute), SLA: core.SLAInfo{Acknowledged: &ack, Breached: true}}}
	incidents := []core.Incident{{ID: "i1", Status: "CLOSED", CreatedAt: now.Add(-3 * time.Hour), UpdatedAt: now}}
	metrics, _, detections, entities := operationalMetrics(alerts, incidents, nil, nil, map[string]interface{}{"events_24h": 86400})
	if len(metrics) < 10 || detections[0].Key != "rule-1" || entities[0].Key != "host-1" {
		t.Fatalf("unexpected metrics: %#v %#v %#v", metrics, detections, entities)
	}
	run := core.ReportRun{ID: "rpt-1", Type: core.ReportTypeSOC, Title: "SOC", Checksum: "sha256:test", Snapshot: map[string]interface{}{"metrics": metrics}}
	payload, contentType, filename, err := (&Service{}).Render(run, "csv")
	if err != nil || !strings.Contains(contentType, "text/csv") || !strings.HasSuffix(filename, ".csv") || !strings.Contains(string(payload), "checksum_sha256") {
		t.Fatalf("CSV export failed: %s %s %v", contentType, filename, err)
	}
}
