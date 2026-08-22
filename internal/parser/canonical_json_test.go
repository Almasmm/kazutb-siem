package parser

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/ingest"
)

func TestCanonicalJSONPreservesEvidenceAndOverridesUntrustedScope(t *testing.T) {
	eventTime := time.Date(2026, 8, 23, 10, 15, 30, 0, time.UTC)
	receivedAt := eventTime.Add(2 * time.Second)
	payload, err := json.Marshal(core.CanonicalEvent{
		ID:           "payload-event",
		TenantID:     "spoofed-tenant",
		CollectorID:  "spoofed-collector",
		EventTime:    eventTime,
		Category:     "process_activity",
		ActivityName: "Process created",
		Source:       core.EventSource{Vendor: "Microsoft", Product: "Sysmon", Type: "endpoint"},
		Device:       core.DeviceRef{Hostname: "dc-01", Criticality: 5},
		Process:      core.ProcessRef{Name: "powershell.exe", CommandLine: "powershell.exe -EncodedCommand SQBFAFgA"},
	})
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := (CanonicalJSON{}).Parse(context.Background(), ingest.RawEnvelope{
		MessageID:      "message-1",
		EventID:        "trusted-event",
		TenantID:       "trusted-tenant",
		CollectorID:    "registered-collector",
		EventTimestamp: eventTime,
		ReceivedAt:     receivedAt,
		RawHash:        "evidence-sha256",
		Payload:        payload,
	})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.ID != "trusted-event" || parsed.TenantID != "trusted-tenant" || parsed.CollectorID != "registered-collector" {
		t.Fatalf("trusted envelope scope was not enforced: %+v", parsed)
	}
	if !parsed.EventTime.Equal(eventTime) || !parsed.IngestTime.Equal(receivedAt) {
		t.Fatalf("event clocks were not preserved: event=%s ingest=%s", parsed.EventTime, parsed.IngestTime)
	}
	if parsed.Raw.Hash != "evidence-sha256" || parsed.Raw.Message != string(payload) || parsed.Raw.Reference == "" {
		t.Fatalf("evidence lineage incomplete: %+v", parsed.Raw)
	}
	if parsed.Parser.ID == "" || parsed.Parser.Version == "" || parsed.Schema.OCSFVersion == "" {
		t.Fatalf("normalization metadata missing: parser=%+v schema=%+v", parsed.Parser, parsed.Schema)
	}
}

func TestCanonicalJSONRejectsMalformedEvent(t *testing.T) {
	_, err := (CanonicalJSON{}).Parse(context.Background(), ingest.RawEnvelope{
		EventID: "event-1", TenantID: "tenant", CollectorID: "collector",
		Payload: []byte(`{"event_time":"not-a-time"}`),
	})
	if !errors.Is(err, ErrParse) {
		t.Fatalf("expected ErrParse, got %v", err)
	}
}
