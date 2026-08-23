package auth

import (
	"net/http"
	"testing"
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
