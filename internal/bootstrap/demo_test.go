package bootstrap

import (
	"context"
	"testing"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/pipeline"
	"github.com/kcsp/platform/internal/soc"
	"github.com/kcsp/platform/internal/store"
)

func TestDemoSeedBuildsStableVerticalSliceAndCanReset(t *testing.T) {
	memory := store.NewMemory()
	engine := pipeline.New(memory)
	service := soc.New(memory)
	seeder := DemoSeeder{Store: memory, Pipeline: engine, SOC: service}
	for run := 0; run < 2; run++ {
		if err := seeder.Seed(context.Background()); err != nil {
			t.Fatalf("seed run %d: %v", run+1, err)
		}
		events := memory.ListEvents(core.DefaultTenantID, store.EventFilter{Limit: 100})
		alerts := memory.ListAlerts(core.DefaultTenantID, store.AlertFilter{Limit: 100})
		incidents := memory.ListIncidents(core.DefaultTenantID, store.IncidentFilter{Limit: 100})
		if len(events) != 10 || len(alerts) != 2 || len(incidents) != 1 {
			t.Fatalf("unexpected seed counts on run %d: events=%d alerts=%d incidents=%d", run+1, len(events), len(alerts), len(incidents))
		}
		if incidents[0].Status != "INVESTIGATION" || incidents[0].RiskScore != 100 {
			t.Fatalf("unexpected seeded incident: %+v", incidents[0])
		}
		if !memory.VerifyAudit(core.DefaultTenantID) {
			t.Fatal("seeded audit chain does not verify")
		}
	}
}
