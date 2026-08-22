package pipeline_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/detection"
	"github.com/kcsp/platform/internal/pipeline"
	"github.com/kcsp/platform/internal/store"
)

const correlationBaseSigma = `title: Authentication failure selector
id: KCSP-BASE-AUTH-FAIL-001
description: Selects failed authentication events for correlation.
level: low
confidence: 90
logsource:
  category: authentication
detection:
  selection:
    category: authentication
    security_result.outcome: failure
  condition: selection
`

const bruteForceCorrelationSigma = `title: Correlated authentication attack
id: KCSP-CORR-BRUTE-001
description: Detects three authentication failures from one source in five minutes.
level: high
confidence: 92
tags:
  - attack.t1110
correlation:
  type: event_count
  rules:
    - KCSP-BASE-AUTH-FAIL-001
  group-by:
    - src_endpoint.ip
  timespan: 5m
  condition:
    gte: 3
`

func TestPublishedCorrelationExecutesAfterEngineRestart(t *testing.T) {
	databaseURL := os.Getenv("KCSP_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("KCSP_TEST_DATABASE_URL is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	tenantID := "pipeline-correlation-" + core.NewID("tenant")
	repository, err := store.OpenPostgres(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	if err := repository.EnsureTenant(ctx, tenantID, "Pipeline Correlation Test"); err != nil {
		t.Fatal(err)
	}
	if err := repository.ResetTenant(ctx, tenantID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_ = repository.ResetTenant(cleanupCtx, tenantID)
	})

	service := detection.NewService(repository)
	baseTime := time.Now().UTC().Add(-time.Minute)
	positiveBase := authEvent("base-positive", baseTime, "10.10.10.9", "student", "failure")
	negativeBase := authEvent("base-negative", baseTime, "10.10.10.9", "student", "success")
	baseDraft, err := service.CreateDraft(ctx, core.DetectionContent{
		TenantID: tenantID, RuleID: "KCSP-BASE-AUTH-FAIL-001", Version: "1.0.0", SigmaYAML: correlationBaseSigma,
		PositiveTests:           []core.DetectionSample{{Name: "failed login", Event: positiveBase}},
		NegativeTests:           []core.DetectionSample{{Name: "successful login", Event: negativeBase}},
		PerformanceBudgetMicros: 50_000, CreatedBy: "correlation-integration",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Validate(ctx, tenantID, baseDraft.RuleID, baseDraft.Version); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Publish(ctx, tenantID, baseDraft.RuleID, baseDraft.Version); err != nil {
		t.Fatal(err)
	}

	positiveSequence := []core.CanonicalEvent{
		authEvent("sample-1", baseTime, "10.10.10.8", "student-a", "failure"),
		authEvent("sample-2", baseTime.Add(time.Second), "10.10.10.8", "student-b", "failure"),
		authEvent("sample-3", baseTime.Add(2*time.Second), "10.10.10.8", "student-c", "failure"),
	}
	negativeSequence := positiveSequence[:2]
	correlationDraft, err := service.CreateDraft(ctx, core.DetectionContent{
		TenantID: tenantID, RuleID: "KCSP-CORR-BRUTE-001", Version: "1.0.0", SigmaYAML: bruteForceCorrelationSigma,
		PositiveTests:           []core.DetectionSample{{Name: "threshold reached", Events: positiveSequence}},
		NegativeTests:           []core.DetectionSample{{Name: "below threshold", Events: negativeSequence}},
		PerformanceBudgetMicros: 50_000, CreatedBy: "correlation-integration",
	})
	if err != nil {
		t.Fatal(err)
	}
	validated, err := service.Validate(ctx, tenantID, correlationDraft.RuleID, correlationDraft.Version)
	if err != nil || !validated.Validation.Valid {
		t.Fatalf("validate correlation content: %+v err=%v", validated.Validation, err)
	}
	if _, err := service.Publish(ctx, tenantID, correlationDraft.RuleID, correlationDraft.Version); err != nil {
		t.Fatal(err)
	}

	engine, err := pipeline.New(ctx, repository)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Ingest(ctx, tenantID, authEvent("runtime-1", baseTime.Add(10*time.Second), "10.10.10.7", "student-a", "failure")); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Ingest(ctx, tenantID, authEvent("runtime-2", baseTime.Add(11*time.Second), "10.10.10.7", "student-b", "failure")); err != nil {
		t.Fatal(err)
	}
	engine, err = pipeline.New(ctx, repository)
	if err != nil {
		t.Fatal(err)
	}
	result, err := engine.Ingest(ctx, tenantID, authEvent("runtime-3", baseTime.Add(12*time.Second), "10.10.10.7", "student-c", "failure"))
	if err != nil {
		t.Fatal(err)
	}
	correlationFound := false
	for _, finding := range result.Findings {
		if finding.Rule.ID == correlationDraft.RuleID {
			correlationFound = true
		}
	}
	if !correlationFound {
		t.Fatalf("published correlation did not execute after engine restart: %+v", result.Findings)
	}
	for _, alert := range result.Alerts {
		if alert.Rule.ID == correlationDraft.RuleID && alert.EventCount == 3 && len(alert.EventIDs) == 3 {
			return
		}
	}
	t.Fatalf("correlation alert does not preserve contributing events: %+v", result.Alerts)
}

func authEvent(id string, at time.Time, sourceIP, user, outcome string) core.CanonicalEvent {
	return core.CanonicalEvent{
		ID: id, EventTime: at, Category: "authentication", ActivityName: "User authentication",
		Source: core.EventSource{Type: "identity", Vendor: "KCSP Test"}, User: core.UserRef{Name: user},
		SrcEndpoint: core.EndpointRef{IP: sourceIP}, SecurityResult: core.SecurityResult{Outcome: outcome},
	}
}
