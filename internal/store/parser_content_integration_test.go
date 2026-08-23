package store

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/ingest"
	"github.com/kcsp/platform/internal/parser"
)

func TestPostgresParserStudioPublishesRuntimeContentAcrossRestart(t *testing.T) {
	dsn := os.Getenv("KCSP_TEST_POSTGRES_URL")
	if dsn == "" {
		t.Skip("KCSP_TEST_POSTGRES_URL is not configured")
	}
	ctx := context.Background()
	repository, err := OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	tenantID := fmt.Sprintf("parser-it-%d", time.Now().UnixNano())
	if err := repository.EnsureTenant(ctx, tenantID, "Parser Studio Integration"); err != nil {
		t.Fatal(err)
	}
	service := parser.NewStudioService(repository)
	draftInput := parser.ParserDraft{
		Name: "Campus NAC JSON", RequestID: "parser-create-once",
		Spec: core.ParserSpec{
			Format: "campus.nac-json", InputKind: "JSON",
			Mappings: map[string]string{"category": "event.category", "user.name": "subject.user", "device.hostname": "device.name", "src_endpoint.ip": "network.ip"},
			Defaults: map[string]string{"source.vendor": "Campus", "source.product": "NAC", "source.type": "network"},
			Tests:    []core.ParserTestCase{{Name: "admission", Payload: `{"event":{"category":"Authentication"},"subject":{"user":"student"},"device":{"name":"lab-01"},"network":{"ip":"10.40.0.7"}}`, Expected: map[string]string{"category": "Authentication", "user.name": "student", "device.hostname": "lab-01"}}},
		},
	}
	draft, err := service.CreateDraft(ctx, tenantID, "parser-engineer", draftInput)
	if err != nil {
		t.Fatal(err)
	}
	duplicate, err := service.CreateDraft(ctx, tenantID, "parser-engineer", draftInput)
	if err != nil || duplicate.Version != draft.Version || duplicate.ParserID != draft.ParserID {
		t.Fatalf("idempotent create failed: %#v %v", duplicate, err)
	}
	validated, err := service.Validate(ctx, tenantID, draft.ParserID, draft.Version)
	if err != nil || !validated.Validation.Valid || validated.Validation.TestsPassed != 1 {
		t.Fatalf("validation failed: %#v %v", validated, err)
	}
	published, err := service.Publish(ctx, tenantID, draft.ParserID, draft.Version)
	if err != nil || published.State != core.ParserStatePublished {
		t.Fatalf("publish failed: %#v %v", published, err)
	}
	registry := parser.NewRegistry(repository)
	event, err := registry.Parse(ctx, ingest.RawEnvelope{TenantID: tenantID, CollectorID: "collector-it", EventID: "evt-parser-it", Format: draftInput.Spec.Format, RawPayload: []byte(draftInput.Spec.Tests[0].Payload), EventTimestamp: time.Now().UTC(), ReceivedAt: time.Now().UTC()})
	if err != nil || event.Parser.ID != draft.ParserID || event.User.Name != "student" {
		t.Fatalf("runtime parse failed: %#v %v", event, err)
	}
	if _, found, err := repository.PublishedParserByFormat(ctx, tenantID+"-other", draftInput.Spec.Format); err != nil || found {
		t.Fatalf("cross-tenant parser lookup escaped isolation: found=%v err=%v", found, err)
	}
	repository.Close()

	restarted, err := OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if persisted, found, err := restarted.PublishedParserByFormat(ctx, tenantID, draftInput.Spec.Format); err != nil || !found || persisted.ParserID != draft.ParserID {
		t.Fatalf("published parser did not survive restart: %#v found=%v err=%v", persisted, found, err)
	}
	if err := restarted.ResetTenant(ctx, tenantID); err != nil {
		t.Fatal(err)
	}
}
