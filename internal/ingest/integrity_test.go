package ingest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
)

const testEnvelopeHMACKey = "kcsp-test-envelope-hmac-key-not-for-runtime"

func testEnvelopeAuthenticator(t *testing.T) *EnvelopeAuthenticator {
	t.Helper()
	authenticator, err := NewEnvelopeAuthenticator(testEnvelopeHMACKey)
	if err != nil {
		t.Fatal(err)
	}
	return authenticator
}

func testRawEnvelope(tenantID string, payload []byte) RawEnvelope {
	digest := sha256.Sum256(payload)
	now := time.Date(2026, time.August, 23, 1, 0, 0, 0, time.UTC)
	return RawEnvelope{
		MessageID: "message-1", EventID: "event-1", TenantID: tenantID, CollectorID: "collector-1",
		EventTimestamp: now.Add(-time.Minute), ReceivedAt: now, Format: "unknown-vendor-v1",
		ContentType: "application/octet-stream", SchemaVersion: "2",
		RawHash: "sha256:" + hex.EncodeToString(digest[:]), RawPayload: append([]byte(nil), payload...),
	}
}

func TestEnvelopeAuthenticatorDetectsIdentityAndPayloadTampering(t *testing.T) {
	t.Parallel()
	authenticator := testEnvelopeAuthenticator(t)
	original := testRawEnvelope("tenant-1", []byte("trusted payload"))
	if err := authenticator.Sign(&original); err != nil {
		t.Fatal(err)
	}
	if err := authenticator.Verify(original); err != nil {
		t.Fatalf("verify signed envelope: %v", err)
	}

	tests := map[string]func(*RawEnvelope){
		"tenant":    func(envelope *RawEnvelope) { envelope.TenantID = "tenant-2" },
		"collector": func(envelope *RawEnvelope) { envelope.CollectorID = "collector-2" },
		"event":     func(envelope *RawEnvelope) { envelope.EventID = "event-2" },
		"payload":   func(envelope *RawEnvelope) { envelope.RawPayload[0] ^= 0xff },
		"hash":      func(envelope *RawEnvelope) { envelope.RawHash = "sha256:" + stringsOfZeroes(64) },
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			candidate := original
			candidate.RawPayload = append([]byte(nil), original.RawPayload...)
			mutate(&candidate)
			if err := authenticator.Verify(candidate); !errors.Is(err, ErrEnvelopeIntegrity) {
				t.Fatalf("tampered envelope error = %v, want ErrEnvelopeIntegrity", err)
			}
		})
	}
}

func TestProcessorRejectsTenantTamperingBeforePersistence(t *testing.T) {
	t.Parallel()
	order := []string{}
	pipeline := &forbiddenPipeline{}
	dlq := &recordingDeadLetter{order: &order}
	authenticator := testEnvelopeAuthenticator(t)
	envelope := testRawEnvelope("tenant-1", []byte("trusted payload"))
	if err := authenticator.Sign(&envelope); err != nil {
		t.Fatal(err)
	}
	envelope.TenantID = "tenant-2"
	body, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	processor := &Processor{
		rawStore: orderedRawStore{order: &order}, parser: orderedFailingParser{order: &order},
		pipeline: pipeline, dlq: dlq, authenticator: authenticator,
	}
	if err := processor.processRecord(context.Background(), &kgo.Record{Value: body}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(order, []string{"dlq"}) {
		t.Fatalf("tampered envelope reached a trusted component: %v", order)
	}
	if pipeline.called || dlq.deadLetter.Stage != "envelope" {
		t.Fatalf("tampered envelope was not quarantined: %+v", dlq.deadLetter)
	}
}

func TestEnvelopeAuthenticatorRequiresStrongKey(t *testing.T) {
	t.Parallel()
	if _, err := NewEnvelopeAuthenticator("short"); !errors.Is(err, ErrEnvelopeIntegrity) {
		t.Fatalf("weak key error = %v, want ErrEnvelopeIntegrity", err)
	}
}

func stringsOfZeroes(length int) string {
	result := make([]byte, length)
	for index := range result {
		result[index] = '0'
	}
	return string(result)
}
