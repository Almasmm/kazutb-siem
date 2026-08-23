package store

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/kcsp/platform/internal/core"
)

func TestPostgresLicensesAndTenantAdministrationAreDurableAndScoped(t *testing.T) {
	dsn := os.Getenv("KCSP_TEST_POSTGRES_URL")
	if dsn == "" {
		t.Skip("KCSP_TEST_POSTGRES_URL is not configured")
	}
	ctx := context.Background()
	repository, err := OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	tenantID := "license-it-" + suffix
	secondTenantID := "license-it-secondary-" + suffix
	if err = repository.EnsureTenant(ctx, tenantID, "License Integration"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	second, err := repository.CreateTenant(ctx, core.Tenant{ID: secondTenantID, DisplayName: "Secondary Integration", State: "ACTIVE", CreatedAt: now, UpdatedAt: now})
	if err != nil || second.ID != secondTenantID {
		t.Fatalf("create tenant failed: %#v err=%v", second, err)
	}
	second, err = repository.SetTenantState(ctx, secondTenantID, "SUSPENDED")
	if err != nil || second.State != "SUSPENDED" {
		t.Fatalf("suspend tenant failed: %#v err=%v", second, err)
	}
	record := core.LicenseRecord{
		TenantID: tenantID, LicenseID: "lic-it-" + suffix, KeyID: "integration-key",
		Payload: core.LicensePayload{
			SchemaVersion: 1, LicenseID: "lic-it-" + suffix, Customer: "Integration", TenantIDs: []string{tenantID}, Modules: []string{core.LicenseModuleSIEMCore},
			Limits: core.LicenseLimits{EPS: 5000, Tenants: 5}, Policy: core.LicensePolicy{IngestAfterExpiry: "BLOCK", ReadOnlyOnExpiry: true},
			IssuedAt: now, NotBefore: now, ExpiresAt: now.Add(365 * 24 * time.Hour), GraceUntil: now.Add(395 * 24 * time.Hour),
		},
		Envelope:    core.LicenseEnvelope{KeyID: "integration-key", Payload: "payload", Signature: "signature"},
		Fingerprint: "sha256:integration", InstalledBy: "integration-admin", RequestID: "license-once-" + suffix, Active: true, InstalledAt: now,
	}
	installed, created, err := repository.InstallLicense(ctx, record)
	if err != nil || !created || installed.LicenseID != record.LicenseID {
		t.Fatalf("install license failed: %#v created=%v err=%v", installed, created, err)
	}
	duplicateInput := record
	duplicateInput.LicenseID = "lic-duplicate-" + suffix
	duplicateInput.Payload.LicenseID = duplicateInput.LicenseID
	duplicate, created, err := repository.InstallLicense(ctx, duplicateInput)
	if err != nil || created || duplicate.LicenseID != record.LicenseID {
		t.Fatalf("idempotent license install failed: %#v created=%v err=%v", duplicate, created, err)
	}
	if _, found, err := repository.CurrentLicense(ctx, secondTenantID); err != nil || found {
		t.Fatalf("cross-tenant license lookup escaped isolation: found=%v err=%v", found, err)
	}
	repository.Close()

	restarted, err := OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	persisted, found, err := restarted.CurrentLicense(ctx, tenantID)
	if err != nil || !found || persisted.Fingerprint != record.Fingerprint || persisted.Payload.Limits.EPS != 5000 {
		t.Fatalf("license did not survive restart: %#v found=%v err=%v", persisted, found, err)
	}
	persistedTenant, err := restarted.GetTenant(ctx, secondTenantID)
	if err != nil || persistedTenant.State != "SUSPENDED" {
		t.Fatalf("tenant state did not survive restart: %#v err=%v", persistedTenant, err)
	}
}
