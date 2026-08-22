package store_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/store"
)

func TestPostgresCorrelationSurvivesRepositoryRestart(t *testing.T) {
	databaseURL := os.Getenv("KCSP_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("KCSP_TEST_DATABASE_URL is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	tenantID := "correlation-" + core.NewID("tenant")
	repository, err := store.OpenPostgres(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { repository.Close() }()
	if err := repository.EnsureTenant(ctx, tenantID, "Correlation Integration Test"); err != nil {
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

	spec := core.CorrelationSpec{Type: core.CorrelationEventCount, Rules: []string{"base-auth"}, TimespanSeconds: 300, Threshold: 3}
	base := time.Now().UTC().Add(-time.Minute)
	observe := func(eventID string, at time.Time) core.CorrelationEvaluation {
		result, err := repository.ObserveCorrelation(ctx, core.CorrelationObservation{
			TenantID: tenantID, RuleID: "KCSP-CORR-RESTART", RuleVersion: "1.0.0", GroupKey: "src=10.2.3.4",
			SourceRuleIDs: []string{"base-auth"}, EventID: eventID, EventTime: at, Value: "student", Spec: spec,
		})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	if observe("restart-event-1", base).Triggered || observe("restart-event-2", base.Add(time.Second)).Triggered {
		t.Fatal("threshold emitted before restart")
	}
	repository.Close()
	repository, err = store.OpenPostgres(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	third := observe("restart-event-3", base.Add(2*time.Second))
	if !third.Triggered || third.Count != 3 || len(third.EventIDs) != 3 {
		t.Fatalf("durable threshold did not emit after restart: %+v", third)
	}
	duplicate := observe("restart-event-3", base.Add(2*time.Second))
	if duplicate.Triggered {
		t.Fatalf("duplicate event emitted a second correlation: %+v", duplicate)
	}
	fourth := observe("restart-event-4", base.Add(3*time.Second))
	if fourth.Triggered {
		t.Fatalf("above-threshold event emitted without a new crossing: %+v", fourth)
	}
}
