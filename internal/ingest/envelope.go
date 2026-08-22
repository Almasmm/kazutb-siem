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
)

const MaxEventBytes = 1 << 20

var ErrInvalidEnvelope = errors.New("invalid ingest envelope")

type RawEnvelope struct {
	MessageID      string          `json:"message_id"`
	EventID        string          `json:"event_id"`
	TenantID       string          `json:"tenant_id"`
	CollectorID    string          `json:"collector_id"`
	EventTimestamp time.Time       `json:"event_timestamp"`
	ReceivedAt     time.Time       `json:"received_at"`
	ContentType    string          `json:"content_type"`
	SchemaVersion  string          `json:"schema_version"`
	RawHash        string          `json:"raw_hash"`
	Payload        json.RawMessage `json:"payload"`
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
	publisher Publisher
	now       func() time.Time
}

func NewGateway(publisher Publisher) *Gateway {
	return &Gateway{publisher: publisher, now: func() time.Time { return time.Now().UTC() }}
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
	now := g.now()
	hash := sha256.Sum256(payload)
	eventID := strings.TrimSpace(header.EventID)
	if eventID == "" {
		identityHash := sha256.Sum256(append([]byte(tenantID+"|"), payload...))
		eventID = "evt_" + hex.EncodeToString(identityHash[:12])
	}
	eventTimestamp := header.EventTime
	if eventTimestamp.IsZero() {
		eventTimestamp = now
	} else {
		eventTimestamp = eventTimestamp.UTC()
	}
	envelope := RawEnvelope{
		MessageID: core.NewID("msg"), EventID: eventID, TenantID: tenantID, CollectorID: collectorID,
		EventTimestamp: eventTimestamp, ReceivedAt: now, ContentType: "application/json",
		SchemaVersion: "1", RawHash: "sha256:" + hex.EncodeToString(hash[:]), Payload: append(json.RawMessage(nil), payload...),
	}
	if err := g.publisher.Publish(ctx, envelope); err != nil {
		return Receipt{}, fmt.Errorf("publish raw event: %w", err)
	}
	return Receipt{MessageID: envelope.MessageID, EventID: envelope.EventID, Status: "QUEUED", Topic: g.publisher.RawTopic(), AcceptedAt: now}, nil
}

type DeadLetter struct {
	Envelope RawEnvelope `json:"envelope"`
	Stage    string      `json:"stage"`
	Error    string      `json:"error"`
	FailedAt time.Time   `json:"failed_at"`
}
