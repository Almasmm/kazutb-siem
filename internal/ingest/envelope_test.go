package ingest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

type recordingPublisher struct {
	records []RawEnvelope
}

func (p *recordingPublisher) Publish(_ context.Context, envelope RawEnvelope) error {
	p.records = append(p.records, envelope)
	return nil
}

func (p *recordingPublisher) RawTopic() string { return "kcsp.test.raw.events.v1" }

func TestGatewayBindsTrustContextAndCreatesDeterministicIdentity(t *testing.T) {
	publisher := &recordingPublisher{}
	gateway := NewGateway(publisher)
	payload := []byte(`{
		"tenant_id":"trusted-tenant",
		"collector_id":"registered-collector",
		"event_time":"2026-08-23T10:15:30Z",
		"category":"process_activity",
		"activity_name":"Process created",
		"source":{"vendor":"Microsoft","product":"Sysmon","type":"endpoint"}
	}`)

	first, err := gateway.SubmitJSON(context.Background(), "trusted-tenant", "registered-collector", payload)
	if err != nil {
		t.Fatal(err)
	}
	second, err := gateway.SubmitJSON(context.Background(), "trusted-tenant", "registered-collector", payload)
	if err != nil {
		t.Fatal(err)
	}
	if first.EventID == "" || first.EventID != second.EventID {
		t.Fatalf("event identity is not deterministic: first=%q second=%q", first.EventID, second.EventID)
	}
	if first.MessageID == second.MessageID {
		t.Fatal("delivery message IDs must be unique")
	}
	if first.Status != "QUEUED" || first.Topic != publisher.RawTopic() {
		t.Fatalf("unexpected receipt: %+v", first)
	}
	if len(publisher.records) != 2 {
		t.Fatalf("expected two published envelopes, got %d", len(publisher.records))
	}
	envelope := publisher.records[0]
	if envelope.TenantID != "trusted-tenant" || envelope.CollectorID != "registered-collector" {
		t.Fatalf("untrusted payload escaped boundary binding: %+v", envelope)
	}
	wantTime := time.Date(2026, 8, 23, 10, 15, 30, 0, time.UTC)
	if !envelope.EventTimestamp.Equal(wantTime) {
		t.Fatalf("event timestamp lost: got %s want %s", envelope.EventTimestamp, wantTime)
	}
	hash := sha256.Sum256(payload)
	if envelope.RawHash != "sha256:"+hex.EncodeToString(hash[:]) {
		t.Fatalf("raw hash mismatch: %q", envelope.RawHash)
	}
}

func TestGatewayRejectsInvalidAndOversizedPayloads(t *testing.T) {
	gateway := NewGateway(&recordingPublisher{})
	cases := []struct {
		name    string
		payload []byte
	}{
		{name: "invalid-json", payload: []byte(`{"event_id":`)},
		{name: "oversized", payload: []byte(`{"message":"` + strings.Repeat("x", MaxEventBytes) + `"}`)},
		{name: "spoofed-principal", payload: []byte(`{
			"tenant_id":"spoofed-tenant",
			"collector_id":"spoofed-collector",
			"event_time":"2026-08-23T10:15:30Z",
			"category":"process_activity",
			"source":{"type":"endpoint"}
		}`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := gateway.SubmitJSON(context.Background(), "tenant", "collector", tc.payload); err == nil {
				t.Fatal("expected invalid envelope error")
			}
		})
	}
}

func TestGatewayPreservesBinarySafeRawSubmission(t *testing.T) {
	publisher := &recordingPublisher{}
	payload := []byte(`<Event><Data Name="CommandLine">a &amp; b</Data></Event>`)
	eventTime := time.Date(2026, 8, 23, 8, 9, 10, 0, time.UTC)
	receipt, err := NewGateway(publisher).SubmitRaw(context.Background(), "tenant", "agent-01", RawSubmission{
		Format: FormatSysmonXML, ContentType: "application/xml", EventID: "sysmon-1",
		EventTimestamp: eventTime, Payload: payload,
	})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.EventID != "sysmon-1" || len(publisher.records) != 1 {
		t.Fatalf("unexpected receipt/publication: receipt=%+v records=%d", receipt, len(publisher.records))
	}
	envelope := publisher.records[0]
	if envelope.Format != FormatSysmonXML || envelope.SchemaVersion != "2" || string(envelope.PayloadBytes()) != string(payload) {
		t.Fatalf("raw envelope changed: %+v", envelope)
	}
	if len(envelope.Payload) != 0 || len(envelope.RawPayload) == 0 || !envelope.EventTimestamp.Equal(eventTime) {
		t.Fatalf("raw payload encoding/timestamp invalid: %+v", envelope)
	}
}
