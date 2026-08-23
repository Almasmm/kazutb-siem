package ephemeral

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestValkeyRateLimiterSharesStateAndExpiresWithoutLeakingRawKey(t *testing.T) {
	valkeyURL := os.Getenv("KCSP_TEST_VALKEY_URL")
	if valkeyURL == "" {
		t.Skip("KCSP_TEST_VALKEY_URL is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	namespace := "kcsp:test:" + strings.ReplaceAll(strings.ToLower(time.Now().UTC().Format("150405.000000000")), ".", "-")
	firstClient, err := OpenValkey(ctx, ValkeyConfig{URL: valkeyURL, Namespace: namespace})
	if err != nil {
		t.Fatal(err)
	}
	defer firstClient.Close()
	secondClient, err := OpenValkey(ctx, ValkeyConfig{URL: valkeyURL, Namespace: namespace})
	if err != nil {
		t.Fatal(err)
	}
	defer secondClient.Close()
	first, err := NewFixedWindowLimiter(firstClient, FixedWindowConfig{Scope: "agent-enrollment", Limit: 2, Window: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewFixedWindowLimiter(secondClient, FixedWindowConfig{Scope: "agent-enrollment", Limit: 2, Window: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	address := "192.0.2.44"
	if allowed, _, err := first.Allow(ctx, address); err != nil || !allowed {
		t.Fatalf("first distributed request: allowed=%v err=%v", allowed, err)
	}
	if allowed, _, err := second.Allow(ctx, address); err != nil || !allowed {
		t.Fatalf("second distributed request: allowed=%v err=%v", allowed, err)
	}
	allowed, retryAfter, err := first.Allow(ctx, address)
	if err != nil || allowed || retryAfter <= 0 || retryAfter > time.Second {
		t.Fatalf("shared limit was not enforced: allowed=%v retry_after=%s err=%v", allowed, retryAfter, err)
	}
	storageKey := first.storageKey(address)
	if strings.Contains(storageKey, address) || !strings.HasPrefix(storageKey, namespace+":rate:agent-enrollment:") {
		t.Fatalf("rate key identity protection failed: key=%q", storageKey)
	}
	time.Sleep(1100 * time.Millisecond)
	if allowed, _, err := second.Allow(ctx, address); err != nil || !allowed {
		t.Fatalf("expired distributed window did not reopen: allowed=%v err=%v", allowed, err)
	}
	if err := firstClient.Health(ctx); err != nil {
		t.Fatal(err)
	}
}
