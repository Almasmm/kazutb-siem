package store_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/store"
	"github.com/kcsp/platform/internal/threatintel"
)

func TestPostgresThreatIntelDeduplicatesExpiresRevokesAndMatches(t *testing.T) {
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
	tenantID := "threat-intel-" + core.NewID("tenant")
	if err := repository.EnsureTenant(ctx, tenantID, "Threat Intel Test"); err != nil {
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
	service := threatintel.NewService(repository)
	feed, err := service.CreateFeed(ctx, tenantID, "ti-analyst", threatintel.FeedDraft{
		Name: "University CSIRT", Kind: "CUSTOM", DefaultConfidence: 80, Tags: []string{"csirt"},
	})
	if err != nil {
		t.Fatal(err)
	}
	confidence := 85
	first, created, err := service.UpsertIndicator(ctx, tenantID, "ti-analyst", threatintel.IndicatorDraft{
		FeedID: feed.ID, Type: core.ThreatIndicatorDomain, Value: "Evil.Example.",
		Confidence: &confidence, Reputation: "MALICIOUS", TTLSeconds: 3600, Tags: []string{"phishing"},
	})
	if err != nil || !created {
		t.Fatalf("create indicator: created=%v item=%+v err=%v", created, first, err)
	}
	lowerConfidence := 60
	deduplicated, created, err := service.UpsertIndicator(ctx, tenantID, "second-source", threatintel.IndicatorDraft{
		FeedID: feed.ID, Type: core.ThreatIndicatorDomain, Value: "evil.example",
		Confidence: &lowerConfidence, Reputation: "SUSPICIOUS", TTLSeconds: 7200, Tags: []string{"malware"},
	})
	if err != nil || created {
		t.Fatalf("deduplicate indicator: created=%v item=%+v err=%v", created, deduplicated, err)
	}
	if deduplicated.ID != first.ID || deduplicated.Version != 2 || deduplicated.Confidence != confidence ||
		len(deduplicated.Tags) != 2 {
		t.Fatalf("unexpected deduplicated indicator: %+v", deduplicated)
	}
	observables := []core.ThreatObservable{{
		Type: core.ThreatIndicatorDomain, NormalizedValue: "evil.example",
		Field: "dst_endpoint.hostname", RawValue: "EVIL.EXAMPLE",
	}}
	matches, err := repository.MatchThreatIntelObservables(ctx, tenantID, "event-ti-1", time.Now().UTC(), observables)
	if err != nil || len(matches) != 1 || matches[0].IndicatorID != first.ID {
		t.Fatalf("match indicator: %+v err=%v", matches, err)
	}
	again, err := repository.MatchThreatIntelObservables(ctx, tenantID, "event-ti-1", time.Now().UTC(), observables)
	if err != nil || len(again) != 1 || again[0].ID != matches[0].ID {
		t.Fatalf("idempotent match: %+v err=%v", again, err)
	}
	storedMatches, err := repository.ListThreatIntelMatches(ctx, tenantID, first.ID, "", 10)
	if err != nil || len(storedMatches) != 1 {
		t.Fatalf("list matches: %+v err=%v", storedMatches, err)
	}
	if _, err := repository.GetThreatIndicator(ctx, "another-tenant", first.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("cross-tenant lookup was not isolated: %v", err)
	}
	revoked, err := service.SetIndicatorState(ctx, tenantID, first.ID, "ti-analyst", core.ThreatIntelStateRevoked, deduplicated.Version)
	if err != nil || revoked.State != core.ThreatIntelStateRevoked {
		t.Fatalf("revoke indicator: %+v err=%v", revoked, err)
	}
	if _, err := service.SetIndicatorState(ctx, tenantID, first.ID, "ti-analyst", core.ThreatIntelStateActive, deduplicated.Version); !errors.Is(err, store.ErrVersionConflict) {
		t.Fatalf("stale indicator version was accepted: %v", err)
	}
	afterRevocation, err := repository.MatchThreatIntelObservables(ctx, tenantID, "event-ti-2", time.Now().UTC(), observables)
	if err != nil || len(afterRevocation) != 0 {
		t.Fatalf("revoked indicator matched: %+v err=%v", afterRevocation, err)
	}
	old := time.Now().UTC().Add(-2 * time.Hour)
	expired, _, err := service.UpsertIndicator(ctx, tenantID, "ti-analyst", threatintel.IndicatorDraft{
		FeedID: feed.ID, Type: core.ThreatIndicatorIPv4, Value: "203.0.113.9",
		Reputation: "MALICIOUS", TTLSeconds: 60, FirstSeen: old, LastSeen: old,
	})
	if err != nil || expired.State != core.ThreatIntelStateExpired {
		t.Fatalf("expired indicator: %+v err=%v", expired, err)
	}
	expiredMatches, err := repository.MatchThreatIntelObservables(ctx, tenantID, "event-ti-3", time.Now().UTC(), []core.ThreatObservable{{
		Type: core.ThreatIndicatorIPv4, NormalizedValue: "203.0.113.9", Field: "src_endpoint.ip", RawValue: "203.0.113.9",
	}})
	if err != nil || len(expiredMatches) != 0 {
		t.Fatalf("expired indicator matched: %+v err=%v", expiredMatches, err)
	}
}
