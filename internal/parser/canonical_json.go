package parser

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/ingest"
)

var ErrParse = errors.New("event parse failed")

type CanonicalJSON struct{}

func (CanonicalJSON) Parse(_ context.Context, envelope ingest.RawEnvelope) (core.CanonicalEvent, error) {
	var event core.CanonicalEvent
	payload := envelope.PayloadBytes()
	if err := json.Unmarshal(payload, &event); err != nil {
		return core.CanonicalEvent{}, fmt.Errorf("%w: decode canonical JSON: %v", ErrParse, err)
	}
	if strings.TrimSpace(event.Category) == "" || strings.TrimSpace(event.Source.Type) == "" {
		return core.CanonicalEvent{}, fmt.Errorf("%w: category and source.type are required", ErrParse)
	}
	event.ID = envelope.EventID
	event.TenantID = envelope.TenantID
	event.CollectorID = envelope.CollectorID
	event.IngestTime = envelope.ReceivedAt
	event.EventTime = envelope.EventTimestamp
	event.Raw.Message = string(payload)
	event.Raw.Hash = envelope.RawHash
	event.Raw.Reference = "clickhouse://raw/" + envelope.TenantID + "/" + envelope.EventID
	event.Parser = core.ParserRef{ID: "kcsp-canonical-json", Version: "1.0.0"}
	if event.Schema.OCSFVersion == "" {
		event.Schema.OCSFVersion = "1.3.0"
	}
	return event, nil
}
