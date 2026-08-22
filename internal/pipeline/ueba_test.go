package pipeline

import (
	"context"
	"testing"
	"time"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/store"
)

type pipelineUEBAStore struct {
	*store.MemoryRepository
	anomaly core.UEBAAnomaly
	calls   int
}

func (s *pipelineUEBAStore) ObserveUEBAEvent(_ context.Context, _ core.CanonicalEvent) (*core.UEBAAnomaly, error) {
	s.calls++
	copy := s.anomaly
	return &copy, nil
}

func TestUEBAAnomalyCreatesBoundedFindingAndAlert(t *testing.T) {
	now := time.Now().UTC()
	repository := &pipelineUEBAStore{MemoryRepository: store.NewMemoryRepository(), anomaly: core.UEBAAnomaly{
		ID: "ueba-1", TenantID: "tenant-a", EventID: "evt-1", EntityType: "user", EntityID: "alice",
		Title: "Explainable behavior deviation", Severity: core.SeverityHigh, RiskScore: 68, Confidence: 86,
		Features:     []core.UEBAFeatureEvidence{{Code: "new_device", Field: "device.hostname", Value: "laptop-9", Score: 55}},
		ModelVersion: "robust-online-v1", FeatureVersion: "ocsf-behavior-v1", Status: core.UEBAAnomalyNew,
	}}
	engine, err := New(context.Background(), repository)
	if err != nil {
		t.Fatal(err)
	}
	result, err := engine.Ingest(context.Background(), "tenant-a", core.CanonicalEvent{
		ID: "evt-1", EventTime: now, IngestTime: now, Category: "process_activity",
		Source: core.EventSource{Type: "sysmon"}, User: core.UserRef{ID: "alice"},
		Device: core.DeviceRef{Hostname: "laptop-9"}, Process: core.ProcessRef{Name: "ordinary.exe"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if repository.calls != 1 || len(result.Findings) != 1 || len(result.Alerts) != 1 {
		t.Fatalf("unexpected UEBA pipeline result: calls=%d findings=%d alerts=%d", repository.calls, len(result.Findings), len(result.Alerts))
	}
	if result.Findings[0].Rule.ID != UEBARuleID || result.Findings[0].RiskScore != 68 || result.Findings[0].Severity == core.SeverityCritical {
		t.Fatalf("unexpected bounded UEBA finding: %+v", result.Findings[0])
	}
}
