package auth

import (
	"errors"
	"net/http"
	"strings"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/platform/tenant"
)

var (
	ErrUnauthenticated = errors.New("authentication required")
	ErrTenantDenied    = errors.New("tenant access denied")
)

type Principal struct {
	ID             string
	DisplayName    string
	Role           string
	Permissions    map[string]bool
	AllowedTenants map[string]bool
	PlatformScope  bool
}

func (p Principal) Can(permission string) bool {
	return p.Permissions["*"] || p.Permissions[permission]
}

func (p Principal) CanAccessTenant(tenantID string) bool {
	return tenant.Valid(tenantID) && (p.PlatformScope || p.AllowedTenants[tenantID])
}

type DemoAuthenticator struct {
	tokens map[string]Principal
}

func NewDemoAuthenticator() *DemoAuthenticator {
	return newDemoAuthenticator("")
}

func NewDemoAuthenticatorWithLab(labToken string) *DemoAuthenticator {
	return newDemoAuthenticator(strings.TrimSpace(labToken))
}

func newDemoAuthenticator(labToken string) *DemoAuthenticator {
	tokens := map[string]Principal{
		"kcsp-demo-l1":                 demoRolePrincipal("user-soc-l1", "Айдана Сәрсен", "soc_l1"),
		"kcsp-demo-l2":                 demoRolePrincipal("user-soc-l2", "Данияр Нұрлан", "soc_l2"),
		"kcsp-demo-auditor":            demoRolePrincipal("user-auditor", "Internal Auditor", "auditor"),
		"kcsp-demo-collector":          demoRolePrincipal("svc-http-collector", "HTTP Collector", "service_collector"),
		"kcsp-demo-detection-engineer": demoRolePrincipal("user-detection-engineer", "Detection Engineer", "detection_engineer"),
		"kcsp-demo-threat-intel":       demoRolePrincipal("user-threat-intel", "Threat Intelligence Analyst", "threat_intelligence_analyst"),
		"kcsp-demo-soar-engineer":      demoRolePrincipal("user-soar-engineer", "SOAR Engineer", "soar_engineer"),
		"kcsp-demo-tenant-admin":       demoRolePrincipal("user-tenant-admin", "Tenant Administrator", "tenant_admin"),
		"kcsp-demo-mssp":               demoRolePrincipal("user-mssp-manager", "MSSP Operations Manager", "mssp_manager"),
		"kcsp-demo-admin":              demoRolePrincipal("user-platform-admin", "KCSP Administrator", "platform_administrator"),
	}
	if labToken != "" {
		principal := demoRolePrincipal("svc-kcsp-lab-admin", "KCSP Hyper-V Lab", "tenant_admin")
		principal.AllowedTenants = map[string]bool{core.LabTenantID: true}
		tokens[labToken] = principal
	}
	return &DemoAuthenticator{tokens: tokens}
}

func demoRolePrincipal(id, name, role string) Principal {
	permissions, roleNames, platformScope := permissionsForRoles([]string{role})
	displayRole := role
	if len(roleNames) > 0 {
		displayRole = roleNames[0]
	}
	allowedTenants := map[string]bool{}
	if !platformScope {
		allowedTenants["university-kulazhanov"] = true
	}
	return Principal{
		ID:             id,
		DisplayName:    name,
		Role:           displayRole,
		Permissions:    permissions,
		AllowedTenants: allowedTenants,
		PlatformScope:  platformScope,
	}
}

func (a *DemoAuthenticator) Authenticate(r *http.Request) (Principal, error) {
	value := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(value, "Bearer ") {
		return Principal{}, ErrUnauthenticated
	}
	principal, ok := a.tokens[strings.TrimSpace(strings.TrimPrefix(value, "Bearer "))]
	if !ok {
		return Principal{}, ErrUnauthenticated
	}
	return principal, nil
}
