package parser

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

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
	provider    PublishedParserProvider
	cacheMu     sync.Mutex
	cache       map[string]dynamicParserSnapshot
}

type PublishedParserProvider interface {
	PublishedParserByFormat(context.Context, string, string) (core.ParserContent, bool, error)
}

type dynamicParserSnapshot struct {
	parser   *CompiledParser
	loadedAt time.Time
}

func NewRegistry(providers ...PublishedParserProvider) *Registry {
	registry := &Registry{
		parsers: map[string]ingest.EnvelopeParser{
			ingest.FormatCanonicalJSON:   CanonicalJSON{},
			ingest.FormatSysmonXML:       SysmonXML{},
			ingest.FormatWindowsEventXML: WindowsEventXML{},
			ingest.FormatLinuxAudit:      LinuxAudit{},
			ingest.FormatSyslog:          Syslog{},
			ingest.FormatCEF:             CEF{},
			ingest.FormatLEEF:            LEEF{},
			ingest.FormatSuricataEVE:     SuricataEVE{},
			ingest.FormatZeekJSON:        ZeekJSON{},
			ingest.FormatGenericJSON:     GenericJSON{},
		},
		descriptors: []Descriptor{
			{ID: "kcsp-canonical-json", Vendor: "KCSP", Product: "Canonical Event", Version: "1.1.0", SchemaCompatibility: []string{"OCSF 1.4.0"}, Formats: []string{ingest.FormatCanonicalJSON}, ReleaseState: "published"},
			{ID: "microsoft-sysmon-xml", Vendor: "Microsoft", Product: "Sysmon", Version: "1.0.0", SchemaCompatibility: []string{"OCSF 1.4.0"}, Formats: []string{ingest.FormatSysmonXML}, ReleaseState: "published"},
			{ID: "microsoft-windows-event-xml", Vendor: "Microsoft", Product: "Windows Event Log", Version: "1.0.0", SchemaCompatibility: []string{"OCSF 1.4.0"}, Formats: []string{ingest.FormatWindowsEventXML}, ReleaseState: "published"},
			{ID: "linux-auditd", Vendor: "Linux", Product: "auditd", Version: "1.0.0", SchemaCompatibility: []string{"OCSF 1.4.0"}, Formats: []string{ingest.FormatLinuxAudit}, ReleaseState: "published"},
			{ID: "ietf-syslog", Vendor: "IETF", Product: "Syslog", Version: "1.0.0", SchemaCompatibility: []string{"OCSF 1.4.0"}, Formats: []string{ingest.FormatSyslog}, ReleaseState: "published"},
			{ID: "arcsite-cef", Vendor: "OpenText", Product: "Common Event Format", Version: "1.0.0", SchemaCompatibility: []string{"OCSF 1.4.0"}, Formats: []string{ingest.FormatCEF}, ReleaseState: "published"},
			{ID: "ibm-leef", Vendor: "IBM", Product: "Log Event Extended Format", Version: "1.0.0", SchemaCompatibility: []string{"OCSF 1.4.0"}, Formats: []string{ingest.FormatLEEF}, ReleaseState: "published"},
			{ID: "oisf-suricata-eve", Vendor: "OISF", Product: "Suricata", Version: "1.0.0", SchemaCompatibility: []string{"OCSF 1.4.0"}, Formats: []string{ingest.FormatSuricataEVE}, ReleaseState: "published"},
			{ID: "zeek-json", Vendor: "Zeek", Product: "Zeek", Version: "1.0.0", SchemaCompatibility: []string{"OCSF 1.4.0"}, Formats: []string{ingest.FormatZeekJSON}, ReleaseState: "published"},
			{ID: "generic-json", Vendor: "KCSP", Product: "Generic JSON", Version: "1.0.0", SchemaCompatibility: []string{"OCSF 1.4.0"}, Formats: []string{ingest.FormatGenericJSON}, ReleaseState: "published"},
		},
		cache: map[string]dynamicParserSnapshot{},
	}
	if len(providers) > 0 {
		registry.provider = providers[0]
	}
	return registry
}

func (r *Registry) Parse(ctx context.Context, envelope ingest.RawEnvelope) (core.CanonicalEvent, error) {
	format := strings.TrimSpace(envelope.Format)
	if format == "" {
		format = ingest.FormatCanonicalJSON
	}
	eventParser, ok := r.parsers[format]
	if ok {
		return parseWithEnvelopeIdentity(ctx, eventParser, envelope)
	}
	if r.provider == nil {
		return core.CanonicalEvent{}, fmt.Errorf("%w: no published parser for format %q", ErrParse, format)
	}
	cacheKey := envelope.TenantID + "\x00" + format
	r.cacheMu.Lock()
	if snapshot, found := r.cache[cacheKey]; found && time.Since(snapshot.loadedAt) < 5*time.Second {
		r.cacheMu.Unlock()
		return parseWithEnvelopeIdentity(ctx, snapshot.parser, envelope)
	}
	r.cacheMu.Unlock()
	content, found, err := r.provider.PublishedParserByFormat(ctx, envelope.TenantID, format)
	if err != nil {
		return core.CanonicalEvent{}, fmt.Errorf("%w: load parser for %q: %v", ErrParse, format, err)
	}
	if !found {
		return core.CanonicalEvent{}, fmt.Errorf("%w: no published parser for format %q", ErrParse, format)
	}
	compiled, err := Compile(content)
	if err != nil {
		return core.CanonicalEvent{}, err
	}
	r.cacheMu.Lock()
	r.cache[cacheKey] = dynamicParserSnapshot{parser: compiled, loadedAt: time.Now()}
	r.cacheMu.Unlock()
	return parseWithEnvelopeIdentity(ctx, compiled, envelope)
}

func parseWithEnvelopeIdentity(ctx context.Context, eventParser ingest.EnvelopeParser, envelope ingest.RawEnvelope) (core.CanonicalEvent, error) {
	event, err := eventParser.Parse(ctx, envelope)
	if err != nil {
		return core.CanonicalEvent{}, err
	}
	event.SourceID = envelope.SourceID
	event.SourceAddress = envelope.SourceAddress
	return event, nil
}

func IsBuiltInFormat(format string) bool {
	_, found := NewRegistry().parsers[strings.ToLower(strings.TrimSpace(format))]
	return found
}

func (r *Registry) Descriptors() []Descriptor {
	result := make([]Descriptor, len(r.descriptors))
	copy(result, r.descriptors)
	return result
}
