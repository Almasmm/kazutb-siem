package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestIPRateLimiterResetsAndIsolatesAddresses(t *testing.T) {
	now := time.Date(2026, time.August, 23, 12, 0, 0, 0, time.UTC)
	limiter := newIPRateLimiter(2, time.Minute)
	limiter.now = func() time.Time { return now }

	if allowed, _ := limiter.Allow("192.0.2.10"); !allowed {
		t.Fatal("first request was rejected")
	}
	if allowed, _ := limiter.Allow("192.0.2.10"); !allowed {
		t.Fatal("second request was rejected")
	}
	if allowed, retryAfter := limiter.Allow("192.0.2.10"); allowed || retryAfter != time.Minute {
		t.Fatalf("third request was not limited: allowed=%v retry_after=%s", allowed, retryAfter)
	}
	if allowed, _ := limiter.Allow("192.0.2.11"); !allowed {
		t.Fatal("an independent address shared the exhausted budget")
	}
	now = now.Add(time.Minute)
	if allowed, _ := limiter.Allow("192.0.2.10"); !allowed {
		t.Fatal("address budget did not reset after the window")
	}
}

func TestAgentEnrollmentRateLimitReturnsRetryAfter(t *testing.T) {
	server := &Server{enrollmentLimiter: newIPRateLimiter(1, time.Minute)}
	handler := server.limitAgentEnrollment(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	first := httptest.NewRequest(http.MethodPost, "/api/v1/agent-enrollment", nil)
	first.RemoteAddr = "192.0.2.20:41000"
	firstResponse := httptest.NewRecorder()
	handler.ServeHTTP(firstResponse, first)
	if firstResponse.Code != http.StatusNoContent {
		t.Fatalf("first request status=%d", firstResponse.Code)
	}

	second := httptest.NewRequest(http.MethodPost, "/api/v1/agent-enrollment", nil)
	second.RemoteAddr = "192.0.2.20:41001"
	secondResponse := httptest.NewRecorder()
	handler.ServeHTTP(secondResponse, second)
	if secondResponse.Code != http.StatusTooManyRequests || secondResponse.Header().Get("Retry-After") == "" {
		t.Fatalf("limited response status=%d retry_after=%q", secondResponse.Code, secondResponse.Header().Get("Retry-After"))
	}
}
