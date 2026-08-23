package entitygraph

import (
	"testing"
	"time"

	"github.com/kcsp/platform/internal/core"
)

func TestProjectBuildsStableInvestigationGraph(t *testing.T) {
	event := core.CanonicalEvent{ID: "evt-1", TenantID: "tenant-a", Category: "Authentication", ActivityName: "Logon", EventTime: time.Date(2026, 8, 23, 10, 0, 0, 0, time.UTC), CollectorID: "collector-1"}
	event.Source.Type, event.Source.Vendor, event.Source.Product = "windows", "Microsoft", "Security"
	event.User.ID, event.User.Name = "u-42", "analyst@university.local"
	event.Device.ID, event.Device.Hostname, event.Device.Department = "d-7", "lab-pc-07", "Cyber Lab"
	event.Process.Name, event.Process.CommandLine = "winlogon.exe", "winlogon.exe"
	event.SrcEndpoint.IP, event.DstEndpoint.IP = "10.12.0.7", "10.12.0.10"

	first := Project(event)
	second := Project(event)
	if len(first.Entities) < 6 || len(first.Relations) < 6 {
		t.Fatalf("projection too small: %d entities, %d relations", len(first.Entities), len(first.Relations))
	}
	if first.Entities[0].ID != second.Entities[0].ID || first.Relations[0].ID != second.Relations[0].ID {
		t.Fatal("projection identifiers are not deterministic")
	}
	foundLogin := false
	for _, relation := range first.Relations {
		if relation.Type == "LOGIN_FROM" {
			foundLogin = true
		}
		if relation.TenantID != event.TenantID || relation.LastEventID != event.ID {
			t.Fatalf("relation lost event scope: %#v", relation)
		}
	}
	if !foundLogin {
		t.Fatal("authentication event did not produce LOGIN_FROM")
	}
}
