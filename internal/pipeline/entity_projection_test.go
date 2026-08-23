package pipeline

import (
	"context"
	"testing"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/store"
)

func TestIngestProjectsEntityGraphIdempotently(t *testing.T) {
	repository := store.NewMemoryRepository()
	engine, err := New(context.Background(), repository)
	if err != nil {
		t.Fatal(err)
	}
	event := core.CanonicalEvent{ID: "evt-entity-projection", Category: "Authentication", ActivityName: "Logon"}
	event.Source.Type = "windows"
	event.User.ID, event.User.Name = "user-1", "student@university.local"
	event.Device.ID, event.Device.Hostname = "device-1", "classroom-01"
	event.SrcEndpoint.IP = "10.10.20.30"
	for attempt := 0; attempt < 2; attempt++ {
		if _, err := engine.Ingest(context.Background(), core.DefaultTenantID, event); err != nil {
			t.Fatal(err)
		}
	}
	entities, err := repository.ListEntities(context.Background(), core.DefaultTenantID, core.EntityFilter{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(entities) < 3 {
		t.Fatalf("expected projected user, device and IP, got %d", len(entities))
	}
	for _, entity := range entities {
		if entity.ObservationCount != 1 {
			t.Fatalf("duplicate ingest incremented %s to %d observations", entity.ID, entity.ObservationCount)
		}
	}
	graph, err := repository.GetEntityGraph(context.Background(), core.DefaultTenantID, entities[0].ID, 2, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(graph.Relations) == 0 || len(graph.EventIDs) != 1 {
		t.Fatalf("incomplete graph: %#v", graph)
	}
}
