package store_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/detection"
	"github.com/kcsp/platform/internal/pipeline"
	"github.com/kcsp/platform/internal/store"
)

const fileCreationSigma = `title: Sensitive startup file created
id: KCSP-SIGMA-FILE-001
status: test
description: Detects file creation in a protected startup path.
author: KCSP Detection Engineering
level: high
confidence: 90
logsource:
  product: windows
  service: sysmon
tags:
  - attack.t1547.001
detection:
  selection:
    category: file_activity
    activity_name: File created
    metadata.target_path|contains: Startup
  condition: selection
`

func TestDetectionContentValidatePublishExecuteRollbackAndDisable(t *testing.T) {
	databaseURL := os.Getenv("KCSP_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("KCSP_TEST_DATABASE_URL is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	tenantID := "detection-" + core.NewID("tenant")
	repository, err := store.OpenPostgres(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	if err := repository.EnsureTenant(ctx, tenantID, "Detection Content Test"); err != nil {
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
	positive := core.CanonicalEvent{Category: "file_activity", ActivityName: "File created", Source: core.EventSource{Type: "endpoint"}, Metadata: map[string]interface{}{"target_path": `C:\Users\student\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\evil.lnk`}}
	negative := core.CanonicalEvent{Category: "file_activity", ActivityName: "File created", Source: core.EventSource{Type: "endpoint"}, Metadata: map[string]interface{}{"target_path": `C:\Temp\notes.txt`}}
	draft, err := service.CreateDraft(ctx, core.DetectionContent{
		TenantID: tenantID, RuleID: "KCSP-SIGMA-FILE-001", Version: "1.0.0", SigmaYAML: fileCreationSigma,
		PositiveTests:           []core.DetectionSample{{Name: "startup persistence", Event: positive}},
		NegativeTests:           []core.DetectionSample{{Name: "ordinary temp file", Event: negative}},
		PerformanceBudgetMicros: 50_000, CreatedBy: "integration-detection-engineer",
	})
	if err != nil || draft.State != "DRAFT" {
		t.Fatalf("create draft: content=%+v err=%v", draft, err)
	}
	if _, err := service.Publish(ctx, tenantID, draft.RuleID, draft.Version); !errors.Is(err, store.ErrVersionConflict) {
		t.Fatalf("unvalidated rule was publishable: %v", err)
	}
	validated, err := service.Validate(ctx, tenantID, draft.RuleID, draft.Version)
	if err != nil || validated.State != "VALIDATED" || !validated.Validation.Valid {
		t.Fatalf("validate content: content=%+v err=%v", validated, err)
	}
	published, err := service.Publish(ctx, tenantID, draft.RuleID, draft.Version)
	if err != nil || published.State != "PUBLISHED" || published.PublishedAt == nil {
		t.Fatalf("publish content: content=%+v err=%v", published, err)
	}

	engine, err := pipeline.New(ctx, repository)
	if err != nil {
		t.Fatal(err)
	}
	positive.ID = "dynamic-rule-event-1"
	result, err := engine.Ingest(ctx, tenantID, positive)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 1 || result.Findings[0].Rule.ID != draft.RuleID || len(result.Alerts) != 1 {
		t.Fatalf("published AST did not execute: %+v", result)
	}
	replay, err := service.Replay(ctx, tenantID, draft.RuleID, draft.Version, time.Now().Add(-5*time.Minute), time.Now().Add(5*time.Minute), 100)
	if err != nil {
		t.Fatal(err)
	}
	if replay.EventsScanned < 1 || replay.Matches < 1 || len(replay.SampleEventIDs) < 1 || replay.SampleEventIDs[0] != positive.ID {
		t.Fatalf("immutable rule replay did not match persisted event: %+v", replay)
	}

	second, err := service.CreateDraft(ctx, core.DetectionContent{
		TenantID: tenantID, RuleID: draft.RuleID, Version: "1.1.0", SigmaYAML: fileCreationSigma,
		PositiveTests: draft.PositiveTests, NegativeTests: draft.NegativeTests,
		PerformanceBudgetMicros: 50_000, CreatedBy: "integration-detection-engineer",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Validate(ctx, tenantID, second.RuleID, second.Version); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Publish(ctx, tenantID, second.RuleID, second.Version); err != nil {
		t.Fatal(err)
	}
	versions, err := service.List(ctx, tenantID)
	if err != nil || len(versions) != 2 {
		t.Fatalf("version inventory: versions=%+v err=%v", versions, err)
	}
	rolledBack, err := service.Rollback(ctx, tenantID, draft.RuleID)
	if err != nil || rolledBack.Version != "1.0.0" || rolledBack.State != "PUBLISHED" {
		t.Fatalf("rollback failed: content=%+v err=%v", rolledBack, err)
	}
	disabled, err := service.Disable(ctx, tenantID, draft.RuleID)
	if err != nil || disabled.State != "DISABLED" {
		t.Fatalf("disable failed: content=%+v err=%v", disabled, err)
	}
	active, err := repository.PublishedDetectionContent(ctx, tenantID)
	if err != nil || len(active) != 0 {
		t.Fatalf("disabled rule remains deployed: active=%+v err=%v", active, err)
	}
}
