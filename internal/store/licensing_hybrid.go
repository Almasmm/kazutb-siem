package store

import (
	"context"

	"github.com/kcsp/platform/internal/core"
)

func (h *Hybrid) GetTenant(ctx context.Context, tenantID string) (core.Tenant, error) {
	return h.control.GetTenant(ctx, tenantID)
}

func (h *Hybrid) ListTenants(ctx context.Context) ([]core.Tenant, error) {
	return h.control.ListTenants(ctx)
}

func (h *Hybrid) CreateTenant(ctx context.Context, tenant core.Tenant) (core.Tenant, error) {
	return h.control.CreateTenant(ctx, tenant)
}

func (h *Hybrid) SetTenantState(ctx context.Context, tenantID, state string) (core.Tenant, error) {
	return h.control.SetTenantState(ctx, tenantID, state)
}

func (h *Hybrid) InstallLicense(ctx context.Context, record core.LicenseRecord) (core.LicenseRecord, bool, error) {
	return h.control.InstallLicense(ctx, record)
}

func (h *Hybrid) CurrentLicense(ctx context.Context, tenantID string) (core.LicenseRecord, bool, error) {
	return h.control.CurrentLicense(ctx, tenantID)
}

func (h *Hybrid) ListLicenses(ctx context.Context, tenantID string) ([]core.LicenseRecord, error) {
	return h.control.ListLicenses(ctx, tenantID)
}
