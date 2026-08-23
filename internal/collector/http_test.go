package collector

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kcsp/platform/internal/agent"
	"github.com/kcsp/platform/internal/ingest"
)

func TestHTTPReceiverPersistsAuthenticatedJSONBatch(t *testing.T) {
	t.Parallel()
	events := []agent.Event{}
	receiver, err := NewHTTPReceiver(HTTPConfig{
		Address: "127.0.0.1:0", AccessToken: "test-secret", AllowInsecureHTTP: true,
		Sink: func(_ context.Context, event agent.Event) error {
			events = append(events, event)
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	body := `[{"timestamp":"2026-08-23T01:02:03Z","action":"login failed","source_ip":"10.0.0.1"},{"timestamp":"2026-08-23T01:02:04Z","action":"login ok","source_ip":"10.0.0.2"}]`
	request := httptest.NewRequest(http.MethodPost, "/v1/events", strings.NewReader(body))
	request.RemoteAddr = "10.20.30.40:12345"
	request.Header.Set("Authorization", "Bearer test-secret")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-KCSP-Source-ID", "vpn-cluster")
	response := httptest.NewRecorder()
	receiver.handler().ServeHTTP(response, request)
	if response.Code != http.StatusAccepted || len(events) != 2 {
		t.Fatalf("response=%d body=%s events=%+v", response.Code, response.Body.String(), events)
	}
	if events[0].Format != ingest.FormatGenericJSON || events[0].SourceAddress != "10.20.30.40" || !strings.Contains(events[0].SourceID, "source:vpn-cluster") {
		t.Fatalf("HTTP source binding failed: %+v", events[0])
	}
	want := time.Date(2026, 8, 23, 1, 2, 3, 0, time.UTC)
	if !events[0].EventTimestamp.Equal(want) {
		t.Fatalf("HTTP original timestamp=%s want=%s", events[0].EventTimestamp, want)
	}
	var receipt struct {
		Status   string `json:"status"`
		Accepted int    `json:"accepted"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &receipt); err != nil || receipt.Status != "PERSISTED" || receipt.Accepted != 2 {
		t.Fatalf("invalid receipt: %+v err=%v", receipt, err)
	}
}

func TestHTTPReceiverFailsClosedAndBackpressures(t *testing.T) {
	t.Parallel()
	if _, err := NewHTTPReceiver(HTTPConfig{Address: "127.0.0.1:0", Sink: func(context.Context, agent.Event) error { return nil }}); err == nil {
		t.Fatal("plain unauthenticated HTTP collector was accepted")
	}
	receiver, err := NewHTTPReceiver(HTTPConfig{
		Address: "127.0.0.1:0", AccessToken: "test-secret", AllowInsecureHTTP: true,
		Sink: func(context.Context, agent.Event) error { return agent.ErrQueueFull },
	})
	if err != nil {
		t.Fatal(err)
	}
	unauthorized := httptest.NewRequest(http.MethodPost, "/v1/events", strings.NewReader(`{"message":"deny"}`))
	unauthorizedResponse := httptest.NewRecorder()
	receiver.handler().ServeHTTP(unauthorizedResponse, unauthorized)
	if unauthorizedResponse.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status=%d", unauthorizedResponse.Code)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/events", strings.NewReader(`{"message":"deny"}`))
	request.Header.Set("Authorization", "Bearer test-secret")
	response := httptest.NewRecorder()
	receiver.handler().ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || response.Header().Get("Retry-After") != "1" {
		t.Fatalf("backpressure status=%d headers=%v", response.Code, response.Header())
	}
}
