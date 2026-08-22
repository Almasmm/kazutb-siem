package store_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/store"
	"github.com/kcsp/platform/internal/threatintel"
)

func TestHybridThreatIntelRetrosearchUsesBoundedClickHouseHunt(t *testing.T) {
	databaseURL := os.Getenv("KCSP_TEST_DATABASE_URL")
	clickhouseURL := os.Getenv("KCSP_TEST_CLICKHOUSE_URL")
	if databaseURL == "" || clickhouseURL == "" {
		t.Skip("KCSP_TEST_DATABASE_URL and KCSP_TEST_CLICKHOUSE_URL are required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	repository, err := store.OpenHybrid(ctx, databaseURL, clickhouseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	tenantID := "ti-retro-" + core.NewID("tenant")
	if err := repository.EnsureTenant(ctx, tenantID, "TI Retrosearch Test"); err != nil {
		t.Fatal(err)
	}
	if err := repository.ResetTenant(ctx, tenantID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cleanupCancel()
		_ = repository.ResetTenant(cleanupCtx, tenantID)
	})
	service := threatintel.NewService(repository)
	feed, err := service.CreateFeed(ctx, tenantID, "ti-analyst", threatintel.FeedDraft{Name: "Retro Feed", Kind: "CUSTOM"})
	if err != nil {
		t.Fatal(err)
	}
	indicator, _, err := service.UpsertIndicator(ctx, tenantID, "ti-analyst", threatintel.IndicatorDraft{
		FeedID: feed.ID, Type: core.ThreatIndicatorDomain, Value: "retro.example", Reputation: "MALICIOUS",
	})
	if err != nil {
		t.Fatal(err)
	}
	eventTime := time.Now().UTC()
	_, duplicate, err := repository.PutEvent(ctx, core.CanonicalEvent{
		ID: "retro-event-" + core.NewID("evt"), TenantID: tenantID, EventTime: eventTime, IngestTime: eventTime,
		Category: "network_activity", Source: core.EventSource{Vendor: "Test", Product: "DNS", Type: "network"},
		DstEndpoint: core.EndpointRef{Hostname: "retro.example"},
		Metadata:    map[string]interface{}{"dns": map[string]interface{}{"query": "RETRO.EXAMPLE."}},
	})
	if err != nil || duplicate {
		t.Fatalf("put retrosearch event: duplicate=%v err=%v", duplicate, err)
	}
	result, err := service.Retrosearch(ctx, tenantID, indicator.ID, core.ThreatIntelRetrosearchRequest{
		Start: eventTime.Add(-time.Minute), End: eventTime.Add(time.Minute), Limit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.CandidateEvents != 1 || result.EventsMatched != 1 || result.Returned != 2 || result.Partial {
		t.Fatalf("unexpected retrosearch result: %+v", result)
	}
}
