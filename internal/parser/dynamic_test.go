package parser

import (
	"context"
	"testing"
	"time"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/ingest"
)

type parserProvider struct{ content core.ParserContent }

func (p parserProvider) PublishedParserByFormat(context.Context, string, string) (core.ParserContent, bool, error) {
	return p.content, true, nil
}

func TestDynamicParserValidatesAndRunsThroughRegistry(t *testing.T) {
	content := core.ParserContent{ParserID: "prs-campus-fw", Version: 3, Spec: core.ParserSpec{
		Format: "campus.firewall-json", InputKind: "JSON",
		Mappings: map[string]string{"category": "event.kind", "user.name": "identity.user", "device.hostname": "host.name", "src_endpoint.ip": "network.src"},
		Defaults: map[string]string{"source.type": "firewall", "source.vendor": "Campus", "source.product": "Edge"},
		Tests:    []core.ParserTestCase{{Name: "allow", Payload: `{"event":{"kind":"Network Activity"},"identity":{"user":"student"},"host":{"name":"edge-1"},"network":{"src":"10.0.0.7"}}`, Expected: map[string]string{"category": "Network Activity", "user.name": "student"}}},
	}}
	report := ValidateContent(content)
	if !report.Valid || report.TestsPassed != 1 {
		t.Fatalf("validation failed: %#v", report)
	}
	registry := NewRegistry(parserProvider{content: content})
	event, err := registry.Parse(context.Background(), ingest.RawEnvelope{TenantID: "tenant-a", EventID: "evt-a", CollectorID: "collector-a", Format: content.Spec.Format, RawPayload: []byte(content.Spec.Tests[0].Payload), EventTimestamp: time.Now().UTC(), ReceivedAt: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	if event.Parser.ID != content.ParserID || event.Parser.Version != "3" || event.User.Name != "student" || event.Source.Type != "firewall" {
		t.Fatalf("unexpected event: %#v", event)
	}
}

func TestDynamicParserRejectsBuiltInOverrideAndUnknownTargets(t *testing.T) {
	report := ValidateDefinition(core.ParserSpec{Format: ingest.FormatSysmonXML, InputKind: "JSON", Mappings: map[string]string{"root.password": "secret"}, Defaults: map[string]string{"category": "x", "source.type": "x"}})
	if report.Valid || len(report.Errors) < 2 {
		t.Fatalf("unsafe parser was accepted: %#v", report)
	}
}
