package bootstrap

import (
	"context"
	"errors"
	"testing"

	"github.com/kcsp/platform/internal/core"
)

type labStoreSpy struct {
	ensured []string
	reset   []string
	audited []string
}

func (s *labStoreSpy) EnsureTenant(_ context.Context, tenantID, _ string) error {
	s.ensured = append(s.ensured, tenantID)
	return nil
}

func (s *labStoreSpy) ResetTenant(_ context.Context, tenantID string) error {
	s.reset = append(s.reset, tenantID)
	return nil
}

func (s *labStoreSpy) AppendAudit(_ context.Context, entry core.AuditEntry) (core.AuditEntry, error) {
	s.audited = append(s.audited, entry.TenantID)
	return entry, nil
}

func TestLabBootstrapIsIdempotentAndPinnedToLabTenant(t *testing.T) {
	store := &labStoreSpy{}
	for range 2 {
		if err := EnsureLabTenant(context.Background(), store, "development"); err != nil {
			t.Fatal(err)
		}
	}
	for _, tenantID := range append(store.ensured, store.audited...) {
		if tenantID != core.LabTenantID {
			t.Fatalf("lab bootstrap touched tenant %q", tenantID)
		}
	}
}

func TestLabBootstrapAndCleanupAreForbiddenInProduction(t *testing.T) {
	store := &labStoreSpy{}
	if err := EnsureLabTenant(context.Background(), store, "production"); !errors.Is(err, ErrLabBootstrapForbidden) {
		t.Fatalf("production bootstrap error = %v", err)
	}
	if err := ResetLabTenant(context.Background(), store, "production"); !errors.Is(err, ErrLabBootstrapForbidden) {
		t.Fatalf("production cleanup error = %v", err)
	}
	if len(store.ensured)+len(store.reset)+len(store.audited) != 0 {
		t.Fatal("production lab operation reached the repository")
	}
}

func TestLabCleanupTouchesOnlyLabTenant(t *testing.T) {
	store := &labStoreSpy{}
	if err := ResetLabTenant(context.Background(), store, "test"); err != nil {
		t.Fatal(err)
	}
	if len(store.reset) != 1 || store.reset[0] != core.LabTenantID {
		t.Fatalf("cleanup targets = %v, want only %q", store.reset, core.LabTenantID)
	}
	if store.reset[0] == core.DefaultTenantID {
		t.Fatal("lab cleanup targeted the university tenant")
	}
}
