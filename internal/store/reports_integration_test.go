package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/kcsp/platform/internal/core"
)

func TestPostgresReportsAreIdempotentTenantScopedAndDurable(t *testing.T) {
	dsn := os.Getenv("KCSP_TEST_POSTGRES_URL")
	if dsn == "" {
		t.Skip("KCSP_TEST_POSTGRES_URL is not configured")
	}
	ctx := context.Background()
	repository, err := OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	tenantID := fmt.Sprintf("reports-it-%d", time.Now().UnixNano())
	if err = repository.EnsureTenant(ctx, tenantID, "Reports Integration"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	run := core.ReportRun{
		ID: "rpt_integration", TenantID: tenantID, Type: core.ReportTypeExecutive,
		Title: "Executive Security Report", Status: "COMPLETED",
		Parameters: core.ReportParameters{Start: now.Add(-24 * time.Hour), End: now},
		Snapshot:   map[string]interface{}{"metrics": []interface{}{map[string]interface{}{"key": "open_incidents", "value": float64(2)}}},
		Checksum:   "sha256:integration", CreatedBy: "soc-l2", RequestID: "report-once", CreatedAt: now, CompletedAt: &now,
	}
	created, wasCreated, err := repository.CreateReportRun(ctx, run)
	if err != nil || !wasCreated || created.ID != run.ID {
		t.Fatalf("create report failed: %#v created=%v err=%v", created, wasCreated, err)
	}
	duplicateInput := run
	duplicateInput.ID = "rpt_should_not_exist"
	duplicateInput.Checksum = "sha256:different"
	duplicate, wasCreated, err := repository.CreateReportRun(ctx, duplicateInput)
	if err != nil || wasCreated || duplicate.ID != run.ID || duplicate.Checksum != run.Checksum {
		t.Fatalf("idempotent report create failed: %#v created=%v err=%v", duplicate, wasCreated, err)
	}
	items, err := repository.ListReportRuns(ctx, tenantID, core.ReportFilter{Type: core.ReportTypeExecutive, Limit: 10})
	if err != nil || len(items) != 1 || items[0].ID != run.ID {
		t.Fatalf("report catalog mismatch: %#v err=%v", items, err)
	}
	if _, err = repository.GetReportRun(ctx, tenantID+"-other", run.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant report lookup escaped isolation: %v", err)
	}
	repository.Close()

	restarted, err := OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	persisted, err := restarted.GetReportRun(ctx, tenantID, run.ID)
	if err != nil || persisted.Checksum != run.Checksum || persisted.CreatedBy != run.CreatedBy {
		t.Fatalf("report did not survive restart: %#v err=%v", persisted, err)
	}
	if err = restarted.ResetTenant(ctx, tenantID); err != nil {
		t.Fatal(err)
	}
}
