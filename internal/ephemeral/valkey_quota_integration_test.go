package ephemeral

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/kcsp/platform/internal/platform/quota"
)

func TestValkeyIngestQuotaIsAtomicAcrossClients(t *testing.T) {
	valkeyURL := strings.TrimSpace(os.Getenv("KCSP_TEST_VALKEY_URL"))
	if valkeyURL == "" {
		t.Skip("KCSP_TEST_VALKEY_URL is not configured")
	}
	ctx := context.Background()
	namespace := fmt.Sprintf("kcsp:test-quota-%d", time.Now().UnixNano())
	first, err := OpenValkey(ctx, ValkeyConfig{URL: valkeyURL, Namespace: namespace})
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := OpenValkey(ctx, ValkeyConfig{URL: valkeyURL, Namespace: namespace})
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	firstLedger, err := NewIngestQuotaLedger(first)
	if err != nil {
		t.Fatal(err)
	}
	secondLedger, err := NewIngestQuotaLedger(second)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	request := quota.IngestReservation{
		TenantID: "tenant-a", Now: now, Events: 1, Bytes: 10,
		Limits: quota.IngestLimits{EventsPerDay: 10, BytesPerDay: 100, EventsPerSec: 10},
	}
	result, err := firstLedger.ReserveIngest(ctx, request)
	if err != nil || !result.NeedsBootstrap || result.Allowed {
		t.Fatalf("missing bootstrap result=%#v err=%v", result, err)
	}
	request.Baseline = &quota.IngestBaseline{Events: 8, Bytes: 80}
	result, err = firstLedger.ReserveIngest(ctx, request)
	if err != nil || !result.Allowed || result.Events != 9 || result.Bytes != 90 {
		t.Fatalf("bootstrap reservation result=%#v err=%v", result, err)
	}
	request.Baseline = nil
	result, err = secondLedger.ReserveIngest(ctx, request)
	if err != nil || !result.Allowed || result.Events != 10 || result.Bytes != 100 {
		t.Fatalf("shared reservation result=%#v err=%v", result, err)
	}
	result, err = firstLedger.ReserveIngest(ctx, request)
	if err != nil || result.Allowed || result.Limit != "events_per_day" || result.NeedsBootstrap {
		t.Fatalf("daily denial result=%#v err=%v", result, err)
	}
	dayKey, _, _ := firstLedger.ingestStorageKeys("tenant-a", now.Truncate(24*time.Hour), now)
	if strings.Contains(dayKey, "tenant-a") {
		t.Fatalf("raw tenant identifier leaked into quota key: %s", dayKey)
	}
}
