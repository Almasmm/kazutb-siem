package ingest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/platform/tenant"
)

const MaxEventBytes = 1 << 20

const (
	FormatCanonicalJSON   = "ocsf-json-v1"
	FormatSysmonXML       = "microsoft-sysmon-xml-v1"
	FormatWindowsEventXML = "microsoft-windows-event-xml-v1"
	FormatLinuxAudit      = "linux-auditd-v1"
	FormatJournaldJSON    = "linux-journald-json-v1"
	FormatSyslog          = "syslog-v1"
	FormatCEF             = "cef-v1"
	FormatLEEF            = "leef-v2"
	FormatSuricataEVE     = "suricata-eve-json-v1"
	FormatZeekJSON        = "zeek-json-v1"
	FormatGenericJSON     = "generic-json-v1"
)

var ErrInvalidEnvelope = errors.New("invalid ingest envelope")

type RawEnvelope struct {
	MessageID      string          `json:"message_id"`
	EventID        string          `json:"event_id"`
	TenantID       string          `json:"tenant_id"`
	CollectorID    string          `json:"collector_id"`
	SourceID       string          `json:"source_id,omitempty"`
	SourceAddress  string          `json:"source_address,omitempty"`
	EventTimestamp time.Time       `json:"event_timestamp"`
	ReceivedAt     time.Time       `json:"received_at"`
	Format         string          `json:"format"`
	ContentType    string          `json:"content_type"`
	SchemaVersion  string          `json:"schema_version"`
	RawHash        string          `json:"raw_hash"`
	Payload        json.RawMessage `json:"payload,omitempty"`
	RawPayload     []byte          `json:"raw_payload,omitempty"`
	Integrity      string          `json:"integrity"`
}

func (e RawEnvelope) PayloadBytes() []byte {
	if len(e.RawPayload) > 0 {
		return e.RawPayload
	}
	return e.Payload
}

type RawSubmission struct {
	Format         string
	ContentType    string
	EventID        string
	EventTimestamp time.Time
	SourceID       string
	SourceAddress  string
	Payload        []byte
}

type Receipt struct {
	MessageID  string    `json:"message_id"`
	EventID    string    `json:"event_id"`
	Status     string    `json:"status"`
	Topic      string    `json:"topic"`
	AcceptedAt time.Time `json:"accepted_at"`
}

type Publisher interface {
	Publish(context.Context, RawEnvelope) error
	RawTopic() string
}

type Gateway struct {
	publisher     Publisher
	authenticator *EnvelopeAuthenticator
	now           func() time.Time
}

func NewGateway(publisher Publisher, authenticator *EnvelopeAuthenticator) *Gateway {
	return &Gateway{publisher: publisher, authenticator: authenticator, now: func() time.Time { return time.Now().UTC() }}
}

func (g *Gateway) SubmitJSON(ctx context.Context, tenantID, collectorID string, payload []byte) (Receipt, error) {
	tenantID = strings.TrimSpace(tenantID)
	collectorID = strings.TrimSpace(collectorID)
	if tenantID == "" || collectorID == "" {
		return Receipt{}, fmt.Errorf("%w: tenant and collector identity are required", ErrInvalidEnvelope)
	}
	if len(payload) == 0 || len(payload) > MaxEventBytes || !json.Valid(payload) {
		return Receipt{}, fmt.Errorf("%w: payload must be one valid JSON value up to %d bytes", ErrInvalidEnvelope, MaxEventBytes)
	}
	var header struct {
		EventID     string    `json:"event_id"`
		EventTime   time.Time `json:"event_time"`
		CollectorID string    `json:"collector_id"`
		Category    string    `json:"category"`
		Source      struct {
			Type string `json:"type"`
		} `json:"source"`
	}
	if err := json.Unmarshal(payload, &header); err != nil {
		return Receipt{}, fmt.Errorf("%w: %v", ErrInvalidEnvelope, err)
	}
	if strings.TrimSpace(header.Category) == "" || strings.TrimSpace(header.Source.Type) == "" {
		return Receipt{}, fmt.Errorf("%w: canonical category and source.type are required", ErrInvalidEnvelope)
	}
	if header.CollectorID != "" && header.CollectorID != collectorID {
		return Receipt{}, fmt.Errorf("%w: collector identity does not match authenticated principal", ErrInvalidEnvelope)
	}
	eventID := strings.TrimSpace(header.EventID)
	return g.submit(ctx, tenantID, collectorID, RawSubmission{
		Format: FormatCanonicalJSON, ContentType: "application/json", EventID: eventID,
		EventTimestamp: header.EventTime, Payload: payload,
	}, true)
}

func (g *Gateway) SubmitRaw(ctx context.Context, tenantID, collectorID string, submission RawSubmission) (Receipt, error) {
	if strings.TrimSpace(submission.Format) == "" || submission.Format == FormatCanonicalJSON {
		return g.SubmitJSON(ctx, tenantID, collectorID, submission.Payload)
	}
	return g.submit(ctx, tenantID, collectorID, submission, false)
}

func (g *Gateway) submit(ctx context.Context, tenantID, collectorID string, submission RawSubmission, canonical bool) (Receipt, error) {
	tenantID = strings.TrimSpace(tenantID)
	collectorID = strings.TrimSpace(collectorID)
	format := strings.TrimSpace(submission.Format)
	if tenantID == "" || collectorID == "" {
		return Receipt{}, fmt.Errorf("%w: tenant and collector identity are required", ErrInvalidEnvelope)
	}
	if !tenant.Valid(tenantID) || len(collectorID) > 256 || !validFormat(format) {
		return Receipt{}, fmt.Errorf("%w: invalid tenant, collector, or format identity", ErrInvalidEnvelope)
	}
	if len(submission.Payload) == 0 || len(submission.Payload) > MaxEventBytes {
		return Receipt{}, fmt.Errorf("%w: payload must contain up to %d bytes", ErrInvalidEnvelope, MaxEventBytes)
	}
	contentType := strings.TrimSpace(submission.ContentType)
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	if len(contentType) > 128 || strings.ContainsAny(contentType, "\r\n") {
		return Receipt{}, fmt.Errorf("%w: invalid content type", ErrInvalidEnvelope)
	}
	sourceID := strings.TrimSpace(submission.SourceID)
	sourceAddress := strings.TrimSpace(submission.SourceAddress)
	if len(sourceID) > 256 || len(sourceAddress) > 256 || strings.ContainsAny(sourceID+sourceAddress, "\r\n") {
		return Receipt{}, fmt.Errorf("%w: invalid source identity", ErrInvalidEnvelope)
	}
	now := g.now()
	hash := sha256.Sum256(submission.Payload)
	eventID := strings.TrimSpace(submission.EventID)
	if eventID == "" {
		identityPrefix := tenantID + "|" + collectorID + "|" + format + "|"
		if sourceID != "" {
			identityPrefix = tenantID + "|" + collectorID + "|" + sourceID + "|" + format + "|"
		}
		identityInput := append([]byte(identityPrefix), submission.Payload...)
		identityHash := sha256.Sum256(identityInput)
		eventID = "evt_" + hex.EncodeToString(identityHash[:12])
	}
	if len(eventID) > 256 || strings.ContainsAny(eventID, "\r\n") {
		return Receipt{}, fmt.Errorf("%w: invalid event identity", ErrInvalidEnvelope)
	}
	eventTimestamp := submission.EventTimestamp
	if eventTimestamp.IsZero() {
		eventTimestamp = now
	} else {
		eventTimestamp = eventTimestamp.UTC()
	}
	envelope := RawEnvelope{
		MessageID: core.NewID("msg"), EventID: eventID, TenantID: tenantID, CollectorID: collectorID,
		SourceID: sourceID, SourceAddress: sourceAddress,
		EventTimestamp: eventTimestamp, ReceivedAt: now, Format: format, ContentType: contentType,
		SchemaVersion: "3", RawHash: "sha256:" + hex.EncodeToString(hash[:]),
	}
	if canonical {
		envelope.Payload = append(json.RawMessage(nil), submission.Payload...)
	} else {
		envelope.RawPayload = append([]byte(nil), submission.Payload...)
	}
	if err := g.authenticator.Sign(&envelope); err != nil {
		return Receipt{}, fmt.Errorf("authenticate raw envelope: %w", err)
	}
	if err := g.publisher.Publish(ctx, envelope); err != nil {
		return Receipt{}, fmt.Errorf("publish raw event: %w", err)
	}
	return Receipt{MessageID: envelope.MessageID, EventID: envelope.EventID, Status: "QUEUED", Topic: g.publisher.RawTopic(), AcceptedAt: now}, nil
}

func validFormat(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '-' || character == '_' || character == '.' {
			continue
		}
		return false
	}
	return true
}

type DeadLetter struct {
	Envelope RawEnvelope `json:"envelope"`
	Stage    string      `json:"stage"`
	Error    string      `json:"error"`
	FailedAt time.Time   `json:"failed_at"`
}
