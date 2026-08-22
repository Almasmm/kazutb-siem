package store_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/store"
)

func TestPostgresRetentionPolicyUsesOptimisticVersioning(t *testing.T) {
	databaseURL := os.Getenv("KCSP_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("KCSP_TEST_DATABASE_URL is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	repository, err := store.OpenPostgres(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	tenantID := "retention-" + core.NewID("tenant")
	if err := repository.EnsureTenant(ctx, tenantID, "Retention Test"); err != nil {
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
	policy, err := repository.RetentionPolicy(ctx, tenantID)
	if err != nil || policy.RawDays != store.DefaultRawRetentionDays || policy.Version != 1 {
		t.Fatalf("default policy: %+v err=%v", policy, err)
	}
	policy.RawDays = 45
	policy.NormalizedDays = 120
	policy.FindingsDays = 365
	policy.EvidenceDays = 3650
	policy.UpdatedBy = "test-admin"
	updated, err := repository.UpdateRetentionPolicy(ctx, policy)
	if err != nil || updated.Version != 2 {
		t.Fatalf("update policy: %+v err=%v", updated, err)
	}
	if _, err := repository.UpdateRetentionPolicy(ctx, policy); !errors.Is(err, store.ErrVersionConflict) {
		t.Fatalf("stale policy update was accepted: %v", err)
	}
	invalid := updated
	invalid.RawDays = invalid.NormalizedDays + 1
	if _, err := repository.UpdateRetentionPolicy(ctx, invalid); err == nil {
		t.Fatal("invalid retention hierarchy was accepted")
	}
}
