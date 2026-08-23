package auth

import (
	"errors"
	"net/http"
	"strings"

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
	read := []string{
		"platform.overview.read", "siem.events.read", "siem.findings.read",
		"soc.alerts.read", "soc.incidents.read", "detection.rules.read", "platform.collectors.read", "siem.rules.read",
		"siem.hunt.read", "siem.hunt.execute", "siem.hunt.manage",
		"siem.parsers.read",
		"platform.retention.read",
		"soc.evidence.read",
		"soc.cases.read",
		"soc.entities.read",
		"ti.indicators.read",
		"soar.playbooks.read", "soar.connectors.read",
		"ueba.read",
		"ai.read", "ai.request",
	}
	l2 := append(append([]string{}, read...), "soc.alerts.manage", "soc.incidents.create", "soc.incidents.manage", "soc.cases.manage", "platform.audit.read", "soc.evidence.write", "soar.playbooks.execute", "soar.actions.approve", "ueba.feedback", "ai.decide", "siem.parsers.write", "siem.parsers.publish")
	return &DemoAuthenticator{tokens: map[string]Principal{
		"kcsp-demo-l1":                 principal("user-soc-l1", "Айдана Сәрсен", "SOC L1", append(read, "soc.alerts.manage", "soc.incidents.create")),
		"kcsp-demo-l2":                 principal("user-soc-l2", "Данияр Нұрлан", "SOC L2", l2),
		"kcsp-demo-auditor":            principal("user-auditor", "Internal Auditor", "Auditor", []string{"platform.overview.read", "platform.audit.read", "soc.alerts.read", "soc.incidents.read", "soc.entities.read"}),
		"kcsp-demo-collector":          principal("svc-http-collector", "HTTP Collector", "Service Account", []string{"siem.events.ingest", "platform.collectors.heartbeat"}),
		"kcsp-demo-detection-engineer": principal("user-detection-engineer", "Detection Engineer", "Detection Engineer", []string{"platform.overview.read", "siem.events.read", "siem.rules.read", "siem.rules.write", "siem.rules.publish", "siem.hunt.read", "siem.hunt.execute", "siem.parsers.read", "siem.parsers.write", "siem.parsers.publish"}),
		"kcsp-demo-threat-intel":       principal("user-threat-intel", "Threat Intelligence Analyst", "Threat Intelligence Analyst", []string{"platform.overview.read", "siem.events.read", "soc.alerts.read", "soc.incidents.read", "ti.indicators.read", "ti.indicators.manage"}),
		"kcsp-demo-soar-engineer":      principal("user-soar-engineer", "SOAR Engineer", "SOAR Engineer", []string{"platform.overview.read", "soc.alerts.read", "soc.incidents.read", "soar.playbooks.read", "soar.playbooks.write", "soar.playbooks.execute", "soar.actions.approve", "soar.connectors.read", "soar.connectors.manage", "soar.connectors.test"}),
		"kcsp-demo-admin": {
			ID:             "user-platform-admin",
			DisplayName:    "KCSP Administrator",
			Role:           "Platform Administrator",
			Permissions:    map[string]bool{"*": true},
			AllowedTenants: map[string]bool{},
			PlatformScope:  true,
		},
	}}
}

func principal(id, name, role string, permissions []string) Principal {
	perms := make(map[string]bool, len(permissions))
	for _, permission := range permissions {
		perms[permission] = true
	}
	return Principal{
		ID:             id,
		DisplayName:    name,
		Role:           role,
		Permissions:    perms,
		AllowedTenants: map[string]bool{"university-kulazhanov": true},
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
