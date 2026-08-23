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

func TestPostgresThreatIntelFeedLeaseQueueAndHealthLifecycle(t *testing.T) {
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
	tenantID := "threat-feed-sync-" + core.NewID("tenant")
	if err := repository.EnsureTenant(ctx, tenantID, "Threat Feed Sync Test"); err != nil {
		t.Fatal(err)
	}
	if err := repository.ResetTenant(ctx, tenantID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		_ = repository.ResetTenant(cleanup, tenantID)
	})
	service := threatintel.NewService(repository)
	feed, err := service.CreateFeed(ctx, tenantID, "ti-analyst", threatintel.FeedDraft{
		Name: "University MISP", Kind: "MISP", SourceURL: "https://misp.example.edu",
		AuthReference: "env://KCSP_TI_FEED_SECRET_INTEGRATION", RefreshIntervalSeconds: 60,
	})
	if err != nil {
		t.Fatal(err)
	}
	if feed.SyncStatus != core.ThreatIntelFeedSyncQueued || feed.NextSyncAt == nil {
		t.Fatalf("feed was not scheduled: %+v", feed)
	}
	queued, err := service.QueueFeedSync(ctx, tenantID, feed.ID)
	if err != nil || queued.SyncStatus != core.ThreatIntelFeedSyncQueued {
		t.Fatalf("queue feed: %+v err=%v", queued, err)
	}
	now := time.Now().UTC()
	claimed, found, err := repository.ClaimThreatIntelFeedSync(ctx, "worker-a", tenantID, now, now.Add(2*time.Minute))
	if err != nil || !found || claimed.ID != feed.ID || claimed.SyncStatus != core.ThreatIntelFeedSyncRunning {
		t.Fatalf("claim feed: %+v found=%v err=%v", claimed, found, err)
	}
	if _, found, err := repository.ClaimThreatIntelFeedSync(ctx, "worker-b", tenantID, now, now.Add(2*time.Minute)); err != nil || found {
		t.Fatalf("leased feed was double-claimed: found=%v err=%v", found, err)
	}
	finished, err := repository.FinishThreatIntelFeedSync(ctx, tenantID, feed.ID, "worker-a", core.ThreatIntelFeedSyncResult{
		Status: core.ThreatIntelFeedSyncSucceeded, Cursor: "cursor-42", Imported: 4, Deduplicated: 2, Rejected: 1,
	}, now.Add(time.Second))
	if err != nil || finished.HealthStatus != core.ThreatIntelFeedHealthHealthy || finished.LastImported != 4 || finished.NextSyncAt == nil {
		t.Fatalf("finish feed: %+v err=%v", finished, err)
	}
	tested, err := repository.RecordThreatIntelFeedTest(ctx, tenantID, feed.ID, core.ThreatIntelFeedTestResult{
		Status: core.ThreatIntelFeedSyncFailed, ErrorClass: "AUTHENTICATION", Detail: "provider rejected credentials", HTTPStatus: 401,
	}, now.Add(2*time.Second))
	if err != nil || tested.HealthStatus != core.ThreatIntelFeedHealthDegraded || tested.LastTestedAt == nil {
		t.Fatalf("record feed test: %+v err=%v", tested, err)
	}
}
