package auth

import (
	"errors"
	"net/http"
	"testing"

	"github.com/kcsp/platform/internal/core"
)

func TestDemoPermissionAndTenantBoundaries(t *testing.T) {
	authenticator := NewDemoAuthenticator()
	tests := []struct {
		token          string
		permission     string
		wantPermission bool
		wantTenant     bool
	}{
		{"kcsp-demo-l1", "soc.alerts.manage", true, true},
		{"kcsp-demo-l1", "soc.incidents.manage", false, true},
		{"kcsp-demo-l2", "soc.incidents.manage", true, true},
		{"kcsp-demo-collector", "siem.events.ingest", true, true},
		{"kcsp-demo-collector", "siem.events.read", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.token+"/"+tt.permission, func(t *testing.T) {
			request, _ := http.NewRequest(http.MethodGet, "http://kcsp.local", nil)
			request.Header.Set("Authorization", "Bearer "+tt.token)
			principal, err := authenticator.Authenticate(request)
			if err != nil {
				t.Fatal(err)
			}
			if got := principal.Can(tt.permission); got != tt.wantPermission {
				t.Fatalf("permission=%v want=%v", got, tt.wantPermission)
			}
			if got := principal.CanAccessTenant("university-kulazhanov"); got != tt.wantTenant {
				t.Fatalf("tenant access=%v want=%v", got, tt.wantTenant)
			}
			if principal.CanAccessTenant("another-tenant") {
				t.Fatal("demo tenant principal accessed another tenant")
			}
		})
	}
}

func TestDemoUsesCanonicalRoleMatrix(t *testing.T) {
	authenticator := NewDemoAuthenticator()
	principal, ok := authenticator.tokens["kcsp-demo-l2"]
	if !ok {
		t.Fatal("demo SOC L2 principal is missing")
	}
	expected, _, _ := permissionsForRoles([]string{"soc_l2"})
	if len(principal.Permissions) != len(expected) {
		t.Fatalf("demo permissions differ from canonical role: got %d, want %d", len(principal.Permissions), len(expected))
	}
	for permission := range expected {
		if !principal.Permissions[permission] {
			t.Fatalf("demo SOC L2 is missing canonical permission %q", permission)
		}
	}
}

func TestUnknownDemoTokenIsRejected(t *testing.T) {
	request, _ := http.NewRequest(http.MethodGet, "http://kcsp.local", nil)
	request.Header.Set("Authorization", "Bearer not-a-real-token")
	if _, err := NewDemoAuthenticator().Authenticate(request); err == nil {
		t.Fatal("unknown token was accepted")
	}
}

func TestLabCredentialCannotBeReusedAcrossTenants(t *testing.T) {
	labToken := "test-kcsp-lab-admin-token-32-bytes"
	request, _ := http.NewRequest(http.MethodGet, "http://kcsp.local", nil)
	request.Header.Set("Authorization", "Bearer "+labToken)
	principal, err := NewDemoAuthenticatorWithLab(labToken).Authenticate(request)
	if err != nil {
		t.Fatal(err)
	}
	if !principal.CanAccessTenant(core.LabTenantID) {
		t.Fatal("lab credential cannot access kcsp-lab")
	}
	if principal.CanAccessTenant(core.DefaultTenantID) || principal.PlatformScope {
		t.Fatal("lab credential can be reused outside kcsp-lab")
	}
	if principal.Role != "Lab Automation" {
		t.Fatalf("lab role = %q, want Lab Automation", principal.Role)
	}
	requiredPermissions := []string{
		"platform.session.read", "platform.overview.read", "platform.collectors.read", "platform.collectors.manage", "platform.audit.read",
		"siem.events.read", "siem.findings.read", "siem.hunt.read", "siem.hunt.execute", "detection.rules.read", "siem.rules.read",
		"soc.alerts.read", "soc.alerts.manage", "soc.incidents.read", "soc.incidents.create", "soc.incidents.manage",
		"soc.cases.read", "soc.cases.manage", "soc.evidence.read",
	}
	if len(principal.Permissions) != len(requiredPermissions) {
		t.Fatalf("lab permission count = %d, want exact allowlist of %d: %+v", len(principal.Permissions), len(requiredPermissions), principal.Permissions)
	}
	for _, permission := range requiredPermissions {
		if !principal.Can(permission) {
			t.Errorf("lab principal missing required permission %q", permission)
		}
	}
	for _, permission := range []string{
		"*", "platform.demo.reset", "mssp.tenants.read", "admin.tenants.manage", "admin.users.manage", "admin.roles.manage", "admin.config.manage",
		"platform.service_accounts.read", "platform.service_accounts.write", "licenses.install", "platform.retention.manage", "siem.parsers.publish",
		"soar.connectors.manage", "soar.actions.approve", "ai.policy.manage",
	} {
		if principal.Can(permission) {
			t.Errorf("lab principal unexpectedly has privileged permission %q", permission)
		}
	}
	if _, err := NewDemoAuthenticator().Authenticate(request); err == nil {
		t.Fatal("lab credential is active when lab bootstrap is disabled")
	}
}

func TestRotatedLabCredentialKeepsPolicyAndRevokesOldToken(t *testing.T) {
	oldToken := "test-kcsp-lab-old-token-value-32-bytes"
	newToken := "test-kcsp-lab-new-token-value-32-bytes"
	authenticator := NewDemoAuthenticatorWithLab(newToken)

	oldRequest, _ := http.NewRequest(http.MethodGet, "http://kcsp.local", nil)
	oldRequest.Header.Set("Authorization", "Bearer "+oldToken)
	if _, err := authenticator.Authenticate(oldRequest); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("rotated authenticator accepted old token: %v", err)
	}

	newRequest, _ := http.NewRequest(http.MethodGet, "http://kcsp.local", nil)
	newRequest.Header.Set("Authorization", "Bearer "+newToken)
	principal, err := authenticator.Authenticate(newRequest)
	if err != nil {
		t.Fatal(err)
	}
	if principal.PlatformScope || !principal.CanAccessTenant(core.LabTenantID) || principal.CanAccessTenant(core.DefaultTenantID) || principal.Can("admin.tenants.manage") {
		t.Fatalf("rotation broadened lab policy: %+v", principal)
	}
}
