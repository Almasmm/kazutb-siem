package agent

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/ingest"
)

func TestForwarderSendsBoundRawEventAndRequiresQueueReceipt(t *testing.T) {
	eventTime := time.Date(2026, 8, 23, 8, 9, 10, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/ingest/events" || r.Header.Get("Authorization") != "Bearer service-token" {
			t.Fatalf("unexpected request: %s headers=%v", r.URL.Path, r.Header)
		}
		if r.Header.Get("X-KCSP-Tenant-ID") != "tenant-a" || r.Header.Get("X-KCSP-Event-Format") != ingest.FormatSysmonXML {
			t.Fatalf("missing source binding headers: %v", r.Header)
		}
		if r.Header.Get("X-KCSP-Event-Timestamp") != eventTime.Format(time.RFC3339Nano) {
			t.Fatalf("source timestamp missing: %v", r.Header)
		}
		if r.Header.Get("X-KCSP-Source-ID") != "host:dc-01" || r.Header.Get("X-KCSP-Source-Address") != "10.20.30.40" {
			t.Fatalf("source identity missing: %v", r.Header)
		}
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(ingest.Receipt{EventID: "event-1", Status: "QUEUED"})
	}))
	defer server.Close()
	forwarder, err := NewForwarder(ForwarderConfig{
		ServerURL: server.URL, TenantID: "tenant-a", AccessToken: "service-token", AllowInsecureHTTP: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer forwarder.Close()
	if _, err := forwarder.Send(t.Context(), Event{
		Format: ingest.FormatSysmonXML, ContentType: "application/xml", EventID: "event-1",
		EventTimestamp: eventTime, SourceID: "host:dc-01", SourceAddress: "10.20.30.40", Payload: []byte("<Event />"),
	}); err != nil {
		t.Fatal(err)
	}
}

func TestForwarderRejectsPlainHTTPByDefault(t *testing.T) {
	if _, err := NewForwarder(ForwarderConfig{ServerURL: "http://kcsp.local", TenantID: "tenant", AccessToken: "token"}); err == nil {
		t.Fatal("expected plain HTTP to be rejected")
	}
}

func TestForwarderSendsCollectorHeartbeat(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/collectors/heartbeat" || r.Header.Get("Authorization") != "Bearer service-token" {
			t.Fatalf("unexpected heartbeat request: %s headers=%v", r.URL.Path, r.Header)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(core.Collector{ID: "collector-1", Health: "ONLINE"})
	}))
	defer server.Close()
	forwarder, err := NewForwarder(ForwarderConfig{
		ServerURL: server.URL, TenantID: "tenant-a", AccessToken: "service-token", AllowInsecureHTTP: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer forwarder.Close()
	collector, err := forwarder.Heartbeat(t.Context(), "0.2.0", map[string]interface{}{"queue_depth": 3})
	if err != nil || collector.ID != "collector-1" {
		t.Fatalf("heartbeat failed: collector=%+v err=%v", collector, err)
	}
}
