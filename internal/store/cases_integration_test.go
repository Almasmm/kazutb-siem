package store_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/kcsp/platform/internal/cases"
	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/store"
)

func TestPostgresCasePersistsWorkflowAndEvidenceLink(t *testing.T) {
	databaseURL := os.Getenv("KCSP_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("KCSP_TEST_DATABASE_URL is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tenantID := "case-store-" + core.NewID("tenant")
	repository, err := store.OpenPostgres(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.EnsureTenant(ctx, tenantID, "Case Store Test"); err != nil {
		repository.Close()
		t.Fatal(err)
	}
	if err := repository.ResetTenant(ctx, tenantID); err != nil {
		repository.Close()
		t.Fatal(err)
	}
	incident := core.Incident{ID: core.NewID("inc"), TenantID: tenantID, Title: "Sysmon PowerShell", Severity: core.SeverityHigh, Status: "INVESTIGATION", Version: 1, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	if _, err := repository.CreateIncident(ctx, incident); err != nil {
		repository.Close()
		t.Fatal(err)
	}
	service := cases.NewService(repository)
	item, duplicate, err := service.Create(ctx, tenantID, "analyst-a", cases.CreateInput{Title: "Forensic investigation", IncidentIDs: []string{incident.ID}, RequestID: "case-request-1"})
	if err != nil || duplicate {
		repository.Close()
		t.Fatalf("create case: duplicate=%v err=%v", duplicate, err)
	}
	item, err = service.AddComment(ctx, tenantID, item.ID, "analyst-a", "Triage package requested", "case-request-2", item.Version)
	if err != nil {
		repository.Close()
		t.Fatal(err)
	}
	evidenceItem := core.EvidenceItem{ID: core.NewID("evd"), TenantID: tenantID, RequestID: "evidence-request-1", CaseID: item.ID, Filename: "triage.zip", ContentType: "application/zip", Size: 42, SHA256: stringsOfLength(64, "b"), Bucket: "evidence", ObjectKey: tenantID + "/triage.zip", RetainUntil: time.Now().UTC().AddDate(1, 0, 0), Uploader: "analyst-a"}
	if _, created, err := repository.ReserveEvidence(ctx, evidenceItem, core.EvidenceMutation{Actor: "analyst-a", Action: "evidence.reserved", Reason: "Case triage", RequestID: evidenceItem.RequestID}); err != nil || !created {
		repository.Close()
		t.Fatalf("reserve case evidence: created=%v err=%v", created, err)
	}
	repository.Close()
	reopened, err := store.OpenPostgres(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	t.Cleanup(func() { _ = reopened.ResetTenant(context.Background(), tenantID) })
	restarted := cases.NewService(reopened)
	stored, err := restarted.Case(ctx, tenantID, item.ID)
	if err != nil || len(stored.Comments) != 1 || len(stored.IncidentIDs) != 1 || len(stored.EvidenceIDs) != 1 || stored.EvidenceIDs[0] != evidenceItem.ID {
		t.Fatalf("case did not survive restart: case=%+v err=%v", stored, err)
	}
	if _, err := restarted.Case(ctx, tenantID+"-other", item.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("cross-tenant case lookup returned %v", err)
	}
	valid, err := reopened.VerifyAudit(ctx, tenantID)
	if err != nil || !valid {
		t.Fatalf("audit chain invalid: valid=%v err=%v", valid, err)
	}
}
