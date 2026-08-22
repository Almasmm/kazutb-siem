package store_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/store"
)

func TestPostgresEvidenceLifecycleAndCustodyChain(t *testing.T) {
	databaseURL := os.Getenv("KCSP_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("KCSP_TEST_DATABASE_URL is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	repository, err := store.OpenPostgres(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	tenantID := "evidence-store-" + core.NewID("tenant")
	if err := repository.EnsureTenant(ctx, tenantID, "Evidence Store Test"); err != nil {
		t.Fatal(err)
	}
	if err := repository.ResetTenant(ctx, tenantID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_ = repository.ResetTenant(cleanupCtx, tenantID)
	})
	item := core.EvidenceItem{
		ID: "evidence-1", TenantID: tenantID, RequestID: "request-1", EventID: "event-1",
		Filename: "sample.txt", ContentType: "text/plain", Size: 12, SHA256: stringsOfLength(64, "a"),
		Bucket: "evidence", ObjectKey: tenantID + "/evidence-1/sample.txt", RetainUntil: time.Now().UTC().AddDate(1, 0, 0),
		Uploader: "analyst-a", Metadata: map[string]interface{}{"source": "integration"},
	}
	reserved, created, err := repository.ReserveEvidence(ctx, item, core.EvidenceMutation{
		Actor: "analyst-a", Action: "evidence.reserved", Reason: "Integration upload", RequestID: "request-1",
	})
	if err != nil || !created || reserved.Status != "PENDING" {
		t.Fatalf("reserve evidence: %+v created=%v err=%v", reserved, created, err)
	}
	duplicate, created, err := repository.ReserveEvidence(ctx, item, core.EvidenceMutation{
		Actor: "analyst-a", Action: "evidence.reserved", Reason: "Duplicate request", RequestID: "request-1",
	})
	if err != nil || created || duplicate.ID != reserved.ID {
		t.Fatalf("idempotent reservation: %+v created=%v err=%v", duplicate, created, err)
	}
	available, err := repository.FinalizeEvidence(ctx, tenantID, item.ID, "version-1", "etag-1", core.EvidenceMutation{
		Actor: "system:evidence", Action: "evidence.uploaded", Reason: "Object stored", RequestID: "request-1",
	})
	if err != nil || available.Status != "AVAILABLE" || available.ObjectVersion != "version-1" {
		t.Fatalf("finalize evidence: %+v err=%v", available, err)
	}
	if _, err := repository.AppendEvidenceCustody(ctx, tenantID, item.ID, core.EvidenceMutation{
		Actor: "analyst-b", Action: "evidence.accessed", Reason: "Incident investigation", RequestID: "request-2",
	}); err != nil {
		t.Fatal(err)
	}
	verified, err := repository.RecordEvidenceVerification(ctx, tenantID, item.ID, true, core.EvidenceMutation{
		Actor: "analyst-b", Action: "evidence.verified", Reason: "Hash verification", RequestID: "request-3",
	})
	if err != nil || verified.VerifiedAt == nil {
		t.Fatalf("record verification: %+v err=%v", verified, err)
	}
	entries, err := repository.ListEvidenceCustody(ctx, tenantID, item.ID)
	if err != nil || len(entries) != 4 {
		t.Fatalf("custody entries: %+v err=%v", entries, err)
	}
	valid, err := repository.VerifyEvidenceCustody(ctx, tenantID, item.ID)
	if err != nil || !valid {
		t.Fatalf("custody chain invalid: valid=%v err=%v", valid, err)
	}
	if _, err := repository.Evidence(ctx, tenantID+"-other", item.ID); err != store.ErrNotFound {
		t.Fatalf("cross-tenant evidence lookup returned %v", err)
	}
}
