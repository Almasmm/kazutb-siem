package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/kcsp/platform/internal/core"
)

var ErrLabBootstrapForbidden = errors.New("lab tenant bootstrap is forbidden outside development/test profiles")

type LabStore interface {
	EnsureTenant(context.Context, string, string) error
	ResetTenant(context.Context, string) error
	AppendAudit(context.Context, core.AuditEntry) (core.AuditEntry, error)
}

func EnsureLabTenant(ctx context.Context, repository LabStore, profile string) error {
	if !labProfileAllowed(profile) {
		return ErrLabBootstrapForbidden
	}
	if err := repository.EnsureTenant(ctx, core.LabTenantID, "KCSP Hyper-V Lab"); err != nil {
		return fmt.Errorf("ensure lab tenant: %w", err)
	}
	if _, err := repository.AppendAudit(ctx, core.AuditEntry{
		TenantID: core.LabTenantID, Actor: "system:lab-bootstrap", Action: "lab.tenant.initialized",
		ResourceType: "tenant", ResourceID: core.LabTenantID, Outcome: "success",
		Metadata: map[string]interface{}{"profile": strings.ToLower(strings.TrimSpace(profile))},
	}); err != nil {
		return fmt.Errorf("audit lab tenant bootstrap: %w", err)
	}
	return nil
}

// ResetLabTenant is intentionally incapable of accepting a caller-provided
// tenant ID. Lab cleanup can therefore never be redirected at a real tenant.
func ResetLabTenant(ctx context.Context, repository LabStore, profile string) error {
	if !labProfileAllowed(profile) {
		return ErrLabBootstrapForbidden
	}
	if err := repository.ResetTenant(ctx, core.LabTenantID); err != nil {
		return fmt.Errorf("reset lab tenant: %w", err)
	}
	return nil
}

func labProfileAllowed(profile string) bool {
	profile = strings.ToLower(strings.TrimSpace(profile))
	return profile == "development" || profile == "test"
}
