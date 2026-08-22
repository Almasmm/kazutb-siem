package store_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/hunt"
	"github.com/kcsp/platform/internal/store"
)

func TestClickHouseHuntUsesTenantBoundKeysetCursor(t *testing.T) {
	clickhouseURL := os.Getenv("KCSP_TEST_CLICKHOUSE_URL")
	if clickhouseURL == "" {
		t.Skip("KCSP_TEST_CLICKHOUSE_URL is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	repository, err := store.OpenClickHouse(ctx, clickhouseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	tenantID := "hunt-" + core.NewID("tenant")
	otherTenant := tenantID + "-other"
	if err := repository.ResetTenant(ctx, tenantID); err != nil {
		t.Fatal(err)
	}
	if err := repository.ResetTenant(ctx, otherTenant); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_ = repository.ResetTenant(cleanupCtx, tenantID)
		_ = repository.ResetTenant(cleanupCtx, otherTenant)
	})
	now := time.Now().UTC()
	events := []core.CanonicalEvent{
		huntEvent(tenantID, "hunt-event-1", now.Add(-3*time.Minute), "authentication", "10.44.0.1"),
		huntEvent(tenantID, "hunt-event-2", now.Add(-2*time.Minute), "authentication", "10.44.0.1"),
		huntEvent(tenantID, "hunt-event-3", now.Add(-time.Minute), "process_activity", "10.44.0.1"),
		huntEvent(otherTenant, "hunt-cross-tenant", now.Add(-30*time.Second), "authentication", "10.44.0.1"),
	}
	for _, event := range events {
		if _, _, err := repository.PutEvent(ctx, event); err != nil {
			t.Fatal(err)
		}
	}
	expression := &core.HuntExpression{All: []core.HuntExpression{
		{Predicate: &core.HuntPredicate{Field: "category", Comparator: "eq", Value: "authentication"}},
		{Predicate: &core.HuntPredicate{Field: "src_endpoint.ip", Comparator: "eq", Value: "10.44.0.1"}},
	}}
	request := core.HuntRequest{Start: now.Add(-time.Hour), End: now.Add(time.Minute), Expression: expression, Limit: 1}
	first, err := repository.HuntEvents(ctx, tenantID, request)
	if err != nil {
		t.Fatal(err)
	}
	if first.Returned != 1 || first.Items[0].ID != "hunt-event-2" || first.NextCursor == "" {
		t.Fatalf("unexpected first hunt page: %+v", first)
	}
	request.Cursor = first.NextCursor
	second, err := repository.HuntEvents(ctx, tenantID, request)
	if err != nil {
		t.Fatal(err)
	}
	if second.Returned != 1 || second.Items[0].ID != "hunt-event-1" {
		t.Fatalf("unexpected second hunt page: %+v", second)
	}
	request.Expression = &core.HuntExpression{Predicate: &core.HuntPredicate{Field: "category", Comparator: "eq", Value: "process_activity"}}
	if _, err := repository.HuntEvents(ctx, tenantID, request); !errors.Is(err, hunt.ErrInvalidQuery) {
		t.Fatalf("cursor was reusable with another query: %v", err)
	}
}

func TestPostgresSavedHuntVisibilityVersionAndExecutionLedger(t *testing.T) {
	databaseURL := os.Getenv("KCSP_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("KCSP_TEST_DATABASE_URL is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	repository, err := store.OpenPostgres(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	tenantID := "saved-hunt-" + core.NewID("tenant")
	if err := repository.EnsureTenant(ctx, tenantID, "Saved Hunt Test"); err != nil {
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
	query := core.HuntRequest{LookbackSeconds: 3600, Limit: 100, Expression: &core.HuntExpression{
		Predicate: &core.HuntPredicate{Field: "category", Comparator: "eq", Value: "authentication"},
	}}
	created, err := repository.CreateSavedHunt(ctx, core.SavedHunt{
		TenantID: tenantID, Name: "Failed authentication", Visibility: "PRIVATE", Query: query, Owner: "analyst-a",
	})
	if err != nil || created.Version != 1 {
		t.Fatalf("create saved hunt: %+v err=%v", created, err)
	}
	if items, err := repository.ListSavedHunts(ctx, tenantID, "analyst-b", false); err != nil || len(items) != 0 {
		t.Fatalf("private hunt leaked to another analyst: %+v err=%v", items, err)
	}
	wrongVersion := created
	wrongVersion.Version = 99
	if _, err := repository.UpdateSavedHunt(ctx, wrongVersion, "analyst-a", false); !errors.Is(err, store.ErrVersionConflict) {
		t.Fatalf("stale saved hunt update was accepted: %v", err)
	}
	created.Visibility = "TENANT"
	updated, err := repository.UpdateSavedHunt(ctx, created, "analyst-a", false)
	if err != nil || updated.Version != 2 {
		t.Fatalf("share saved hunt: %+v err=%v", updated, err)
	}
	if items, err := repository.ListSavedHunts(ctx, tenantID, "analyst-b", false); err != nil || len(items) != 1 {
		t.Fatalf("tenant hunt is not visible: %+v err=%v", items, err)
	}
	if _, err := repository.UpdateSavedHunt(ctx, updated, "analyst-b", false); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("non-owner updated shared hunt: %v", err)
	}
	execution := core.HuntExecution{
		ID: "execution-1", TenantID: tenantID, SavedHuntID: updated.ID, Actor: "analyst-a", Query: query,
		QueryHash: stringsOfLength(64, "a"), Status: "SUCCEEDED", Returned: 2, DurationMicros: 1200,
	}
	if err := repository.RecordHuntExecution(ctx, execution); err != nil {
		t.Fatal(err)
	}
	executions, err := repository.ListHuntExecutions(ctx, tenantID, updated.ID, "analyst-a", false, 10)
	if err != nil || len(executions) != 1 || executions[0].Returned != 2 {
		t.Fatalf("execution ledger: %+v err=%v", executions, err)
	}
}

func huntEvent(tenantID, id string, at time.Time, category, sourceIP string) core.CanonicalEvent {
	return core.CanonicalEvent{
		ID: id, TenantID: tenantID, EventTime: at, IngestTime: at.Add(time.Second), Category: category,
		ActivityName: "Hunt integration event", Source: core.EventSource{Type: "test", Vendor: "KCSP"},
		SrcEndpoint: core.EndpointRef{IP: sourceIP}, Process: core.ProcessRef{Name: "powershell.exe", CommandLine: "Write-Output safe"},
		Raw: core.RawRef{Hash: "sha256:" + stringsOfLength(64, "b")},
	}
}

func stringsOfLength(length int, value string) string {
	result := ""
	for len(result) < length {
		result += value
	}
	return result[:length]
}
