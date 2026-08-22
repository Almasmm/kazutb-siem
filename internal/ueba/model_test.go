package ueba

import (
	"testing"
	"time"

	"github.com/kcsp/platform/internal/core"
)

func TestEvaluateColdStartThenExplainableDeviation(t *testing.T) {
	started := time.Date(2026, 8, 20, 8, 0, 0, 0, time.UTC)
	baseline := NewBaseline("tenant-a", "user", "alice", "Alice", "engineering|standard", started)
	peer := NewBaseline("tenant-a", "peer", "engineering|standard", "engineering|standard", "engineering|standard", started)
	for index := 0; index < 50; index++ {
		event := modelEvent(started.Add(time.Duration(index)*time.Minute), "evt-training", "workstation-01", "10.0.0.10", "powershell.exe", "intranet.local")
		if anomaly := Evaluate(&baseline, &peer, event, VolumeStats{}, DefaultConfig(), event.IngestTime); anomaly != nil {
			t.Fatalf("stable cold-start observation emitted anomaly: %+v", anomaly)
		}
	}
	novelAt := started.Add(10 * time.Hour)
	novel := modelEvent(novelAt, "evt-novel", "unknown-laptop", "198.51.100.40", "rare-admin-tool.exe", "unseen.example")
	novel.Metadata = map[string]interface{}{"src_country": "ZZ", "src_asn": "AS64550"}
	anomaly := Evaluate(&baseline, &peer, novel, VolumeStats{}, DefaultConfig(), novelAt)
	if anomaly == nil {
		t.Fatal("mature baseline did not emit an explainable deviation")
	}
	if anomaly.Severity == core.SeverityCritical || anomaly.RiskScore > 75 || anomaly.RiskScore < DefaultConfig().MinimumRisk {
		t.Fatalf("UEBA risk escaped bounded policy: %+v", anomaly)
	}
	if len(anomaly.Features) < 3 || anomaly.ModelVersion != ModelVersion || anomaly.FeatureVersion != FeatureVersion {
		t.Fatalf("anomaly evidence/version metadata is incomplete: %+v", anomaly)
	}
	if anomaly.Explanation["deterministic"] != true || anomaly.Confidence < 1 {
		t.Fatalf("anomaly explanation is incomplete: %+v", anomaly.Explanation)
	}
}

func TestBuildVolumeStatsUsesRobustDistribution(t *testing.T) {
	stats := BuildVolumeStats(20, []int{1, 2, 2, 2, 3, 100})
	if stats.Median != 2 || stats.MAD <= 0 || stats.RobustZScore <= 3 {
		t.Fatalf("unexpected robust volume statistics: %+v", stats)
	}
}

func modelEvent(at time.Time, id, device, ip, process, destination string) core.CanonicalEvent {
	return core.CanonicalEvent{
		ID: id, TenantID: "tenant-a", EventTime: at, IngestTime: at,
		Category: "process_activity", ActivityName: "Process created", Source: core.EventSource{Type: "sysmon"},
		User:        core.UserRef{ID: "alice", Name: "Alice"},
		Device:      core.DeviceRef{ID: device, Hostname: device, IP: ip, Department: "Engineering"},
		SrcEndpoint: core.EndpointRef{IP: ip}, DstEndpoint: core.EndpointRef{Hostname: destination},
		Process: core.ProcessRef{Name: process},
	}
}
