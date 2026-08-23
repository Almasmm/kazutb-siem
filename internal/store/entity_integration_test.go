package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/entitygraph"
)

func TestPostgresEntityGraphPersistsAndIsTenantScoped(t *testing.T) {
	dsn := os.Getenv("KCSP_TEST_POSTGRES_URL")
	if dsn == "" {
		t.Skip("KCSP_TEST_POSTGRES_URL is not configured")
	}
	ctx := context.Background()
	repository, err := OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	tenantID := fmt.Sprintf("entity-it-%d", time.Now().UnixNano())
	otherTenant := tenantID + "-other"
	if err := repository.EnsureTenant(ctx, tenantID, "Entity Integration"); err != nil {
		t.Fatal(err)
	}
	if err := repository.EnsureTenant(ctx, otherTenant, "Other Tenant"); err != nil {
		t.Fatal(err)
	}
	event := core.CanonicalEvent{ID: "evt-entity-it", TenantID: tenantID, Category: "Network Activity", EventTime: time.Now().UTC(), IngestTime: time.Now().UTC()}
	event.Source.Type = "firewall"
	event.Device.ID, event.Device.Hostname = "asset-1", "gateway-01"
	event.SrcEndpoint.IP, event.DstEndpoint.IP = "10.0.0.1", "198.51.100.7"
	if err := repository.ObserveEntityEvent(ctx, event); err != nil {
		t.Fatal(err)
	}
	if err := repository.ObserveEntityEvent(ctx, event); err != nil {
		t.Fatal(err)
	}
	items, err := repository.ListEntities(ctx, tenantID, core.EntityFilter{Limit: 100})
	if err != nil || len(items) < 3 {
		t.Fatalf("entities=%d err=%v", len(items), err)
	}
	for _, item := range items {
		if item.ObservationCount != 1 {
			t.Fatalf("non-idempotent observation count: %#v", item)
		}
	}
	graph, err := repository.GetEntityGraph(ctx, tenantID, items[0].ID, 2, 100)
	if err != nil || len(graph.Relations) == 0 {
		t.Fatalf("graph=%#v err=%v", graph, err)
	}
	if _, err := repository.GetEntity(ctx, otherTenant, items[0].ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant lookup escaped isolation: %v", err)
	}
	projection := entitygraph.Project(event)
	if err := repository.ResetTenant(ctx, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.GetEntity(ctx, tenantID, projection.Entities[0].ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("reset retained entity: %v", err)
	}
	repository.Close()

	restarted, err := OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
}
