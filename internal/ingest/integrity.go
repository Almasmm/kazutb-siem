package ingest

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kcsp/platform/internal/platform/tenant"
)

const envelopeIntegrityPrefix = "hmac-sha256:"

var ErrEnvelopeIntegrity = errors.New("invalid envelope integrity")

// EnvelopeAuthenticator binds trusted ingest identity to event content before
// the envelope enters Kafka. The processor verifies this binding before raw
// persistence, parsing, or detection.
type EnvelopeAuthenticator struct {
	key []byte
}

func NewEnvelopeAuthenticator(key string) (*EnvelopeAuthenticator, error) {
	if len(key) < 32 {
		return nil, fmt.Errorf("%w: HMAC key must contain at least 32 bytes", ErrEnvelopeIntegrity)
	}
	return &EnvelopeAuthenticator{key: append([]byte(nil), key...)}, nil
}

func (a *EnvelopeAuthenticator) Sign(envelope *RawEnvelope) error {
	if a == nil {
		return fmt.Errorf("%w: authenticator is not configured", ErrEnvelopeIntegrity)
	}
	if envelope == nil {
		return fmt.Errorf("%w: envelope is required", ErrEnvelopeIntegrity)
	}
	if err := validateEnvelopeForIntegrity(*envelope); err != nil {
		return err
	}
	envelope.Integrity = envelopeIntegrityPrefix + hex.EncodeToString(a.mac(*envelope))
	return nil
}

func (a *EnvelopeAuthenticator) Verify(envelope RawEnvelope) error {
	if a == nil {
		return fmt.Errorf("%w: authenticator is not configured", ErrEnvelopeIntegrity)
	}
	if err := validateEnvelopeForIntegrity(envelope); err != nil {
		return err
	}
	if !strings.HasPrefix(envelope.Integrity, envelopeIntegrityPrefix) {
		return fmt.Errorf("%w: signature is missing", ErrEnvelopeIntegrity)
	}
	actual, err := hex.DecodeString(strings.TrimPrefix(envelope.Integrity, envelopeIntegrityPrefix))
	if err != nil || len(actual) != sha256.Size || !hmac.Equal(actual, a.mac(envelope)) {
		return fmt.Errorf("%w: signature mismatch", ErrEnvelopeIntegrity)
	}
	return nil
}

func (a *EnvelopeAuthenticator) mac(envelope RawEnvelope) []byte {
	payload, _ := json.Marshal(struct {
		MessageID      string `json:"message_id"`
		EventID        string `json:"event_id"`
		TenantID       string `json:"tenant_id"`
		CollectorID    string `json:"collector_id"`
		EventTimestamp string `json:"event_timestamp"`
		ReceivedAt     string `json:"received_at"`
		Format         string `json:"format"`
		ContentType    string `json:"content_type"`
		SchemaVersion  string `json:"schema_version"`
		RawHash        string `json:"raw_hash"`
	}{
		MessageID: envelope.MessageID, EventID: envelope.EventID, TenantID: envelope.TenantID,
		CollectorID: envelope.CollectorID, EventTimestamp: envelope.EventTimestamp.UTC().Format(time.RFC3339Nano),
		ReceivedAt: envelope.ReceivedAt.UTC().Format(time.RFC3339Nano), Format: envelope.Format,
		ContentType: envelope.ContentType, SchemaVersion: envelope.SchemaVersion, RawHash: envelope.RawHash,
	})
	mac := hmac.New(sha256.New, a.key)
	_, _ = mac.Write(payload)
	return mac.Sum(nil)
}

func validateEnvelopeForIntegrity(envelope RawEnvelope) error {
	if !tenant.Valid(envelope.TenantID) {
		return fmt.Errorf("%w: tenant ID is not canonical", ErrEnvelopeIntegrity)
	}
	if !validEnvelopeIdentity(envelope.MessageID, 256) || !validEnvelopeIdentity(envelope.EventID, 256) ||
		!validEnvelopeIdentity(envelope.CollectorID, 256) {
		return fmt.Errorf("%w: identity fields are invalid", ErrEnvelopeIntegrity)
	}
	if envelope.EventTimestamp.IsZero() || envelope.ReceivedAt.IsZero() || !validFormat(envelope.Format) ||
		envelope.SchemaVersion == "" || len(envelope.SchemaVersion) > 32 {
		return fmt.Errorf("%w: envelope metadata is invalid", ErrEnvelopeIntegrity)
	}
	if len(envelope.ContentType) == 0 || len(envelope.ContentType) > 128 || strings.ContainsAny(envelope.ContentType, "\r\n") {
		return fmt.Errorf("%w: content type is invalid", ErrEnvelopeIntegrity)
	}
	if len(envelope.Payload) > 0 && len(envelope.RawPayload) > 0 {
		return fmt.Errorf("%w: multiple payload representations", ErrEnvelopeIntegrity)
	}
	payload := envelope.PayloadBytes()
	if len(payload) == 0 || len(payload) > MaxEventBytes {
		return fmt.Errorf("%w: payload size is invalid", ErrEnvelopeIntegrity)
	}
	if len(envelope.Payload) > 0 && !json.Valid(envelope.Payload) {
		return fmt.Errorf("%w: canonical payload is invalid", ErrEnvelopeIntegrity)
	}
	digest := sha256.Sum256(payload)
	if envelope.RawHash != "sha256:"+hex.EncodeToString(digest[:]) {
		return fmt.Errorf("%w: payload hash mismatch", ErrEnvelopeIntegrity)
	}
	return nil
}

func validEnvelopeIdentity(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && value == strings.TrimSpace(value) && !strings.ContainsAny(value, "\r\n")
}
