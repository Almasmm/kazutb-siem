package parser

import (
	"context"
	"fmt"
	"strings"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/ingest"
)

type Descriptor struct {
	ID                  string   `json:"parser_id"`
	Vendor              string   `json:"vendor"`
	Product             string   `json:"product"`
	Version             string   `json:"version"`
	SchemaCompatibility []string `json:"schema_compatibility"`
	Formats             []string `json:"formats"`
	ReleaseState        string   `json:"release_state"`
}

type Registry struct {
	parsers     map[string]ingest.EnvelopeParser
	descriptors []Descriptor
}

func NewRegistry() *Registry {
	return &Registry{
		parsers: map[string]ingest.EnvelopeParser{
			ingest.FormatCanonicalJSON: CanonicalJSON{},
			ingest.FormatSysmonXML:     SysmonXML{},
		},
		descriptors: []Descriptor{
			{ID: "kcsp-canonical-json", Vendor: "KCSP", Product: "Canonical Event", Version: "1.1.0", SchemaCompatibility: []string{"OCSF 1.4.0"}, Formats: []string{ingest.FormatCanonicalJSON}, ReleaseState: "published"},
			{ID: "microsoft-sysmon-xml", Vendor: "Microsoft", Product: "Sysmon", Version: "1.0.0", SchemaCompatibility: []string{"OCSF 1.4.0"}, Formats: []string{ingest.FormatSysmonXML}, ReleaseState: "published"},
		},
	}
}

func (r *Registry) Parse(ctx context.Context, envelope ingest.RawEnvelope) (core.CanonicalEvent, error) {
	format := strings.TrimSpace(envelope.Format)
	if format == "" {
		format = ingest.FormatCanonicalJSON
	}
	eventParser, ok := r.parsers[format]
	if !ok {
		return core.CanonicalEvent{}, fmt.Errorf("%w: no published parser for format %q", ErrParse, format)
	}
	return eventParser.Parse(ctx, envelope)
}

func (r *Registry) Descriptors() []Descriptor {
	result := make([]Descriptor, len(r.descriptors))
	copy(result, r.descriptors)
	return result
}
