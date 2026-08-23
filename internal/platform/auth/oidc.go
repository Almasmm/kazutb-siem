package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/kcsp/platform/internal/platform/tenant"
)

type OIDCConfig struct {
	IssuerURL           string
	ClientID            string
	TenantClaim         string
	RolesClaim          string
	PermissionClaim     string
	AllowInsecureIssuer bool
}

type OIDCAuthenticator struct {
	verifier        *oidc.IDTokenVerifier
	clientID        string
	tenantClaim     string
	rolesClaim      string
	permissionClaim string
}

func NewOIDCAuthenticator(ctx context.Context, config OIDCConfig) (*OIDCAuthenticator, error) {
	config.IssuerURL = strings.TrimSpace(config.IssuerURL)
	config.ClientID = strings.TrimSpace(config.ClientID)
	if config.IssuerURL == "" || config.ClientID == "" {
		return nil, errors.New("OIDC issuer URL and client ID are required")
	}
	issuerURL, err := url.Parse(config.IssuerURL)
	if err != nil || !issuerURL.IsAbs() || issuerURL.Host == "" {
		return nil, errors.New("OIDC issuer URL must be an absolute URL with a host")
	}
	if issuerURL.User != nil || issuerURL.RawQuery != "" || issuerURL.Fragment != "" {
		return nil, errors.New("OIDC issuer URL must not contain user info, query parameters, or a fragment")
	}
	if !strings.EqualFold(issuerURL.Scheme, "https") && !(config.AllowInsecureIssuer && strings.EqualFold(issuerURL.Scheme, "http")) {
		return nil, errors.New("OIDC issuer URL must use HTTPS")
	}
	provider, err := oidc.NewProvider(ctx, config.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("discover OIDC provider: %w", err)
	}
	return &OIDCAuthenticator{
		verifier:        provider.Verifier(&oidc.Config{ClientID: config.ClientID}),
		clientID:        config.ClientID,
		tenantClaim:     defaultClaim(config.TenantClaim, "kcsp_tenants"),
		rolesClaim:      defaultClaim(config.RolesClaim, "kcsp_roles"),
		permissionClaim: defaultClaim(config.PermissionClaim, "kcsp_permissions"),
	}, nil
}

func (a *OIDCAuthenticator) Authenticate(r *http.Request) (Principal, error) {
	rawToken, err := bearerToken(r.Header.Get("Authorization"))
	if err != nil {
		return Principal{}, err
	}
	token, err := a.verifier.Verify(r.Context(), rawToken)
	if err != nil {
		return Principal{}, fmt.Errorf("%w: invalid OIDC token", ErrUnauthenticated)
	}
	claims := map[string]interface{}{}
	if err := token.Claims(&claims); err != nil {
		return Principal{}, fmt.Errorf("%w: invalid OIDC claims", ErrUnauthenticated)
	}
	subject := stringClaim(claims, "sub")
	if subject == "" {
		return Principal{}, fmt.Errorf("%w: token subject is required", ErrUnauthenticated)
	}

	roles := collectRoles(claims, a.clientID, a.rolesClaim)
	permissions, roleNames, platformScope := permissionsForRoles(roles)
	for _, permission := range stringSliceClaim(claims, a.permissionClaim) {
		if knownPermissions[permission] {
			grantPermission(permissions, permission)
		}
	}
	for _, permission := range strings.Fields(stringClaim(claims, "scope")) {
		if knownPermissions[permission] {
			grantPermission(permissions, permission)
		}
	}
	tenants := map[string]bool{}
	for _, tenantID := range stringSliceClaim(claims, a.tenantClaim) {
		if err := addTenantMembership(tenants, tenantID); err != nil {
			return Principal{}, err
		}
	}
	if tenantID := stringClaim(claims, "tenant_id"); tenantID != "" {
		if err := addTenantMembership(tenants, tenantID); err != nil {
			return Principal{}, err
		}
	}
	if !platformScope && len(tenants) == 0 {
		return Principal{}, fmt.Errorf("%w: no KCSP tenant membership", ErrUnauthenticated)
	}
	displayName := firstClaim(claims, "name", "preferred_username", "email")
	if displayName == "" {
		displayName = subject
	}
	role := "Authenticated user"
	if len(roleNames) > 0 {
		role = roleNames[0]
	}
	return Principal{
		ID: subject, DisplayName: displayName, Role: role,
		Permissions: permissions, AllowedTenants: tenants, PlatformScope: platformScope,
	}, nil
}

func addTenantMembership(memberships map[string]bool, value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	if err := tenant.Validate(value); err != nil {
		return fmt.Errorf("%w: invalid KCSP tenant membership", ErrUnauthenticated)
	}
	memberships[value] = true
	return nil
}

func bearerToken(value string) (string, error) {
	parts := strings.Fields(strings.TrimSpace(value))
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
		return "", ErrUnauthenticated
	}
	return parts[1], nil
}

func defaultClaim(value, fallback string) string {
	if value = strings.TrimSpace(value); value != "" {
		return value
	}
	return fallback
}

func firstClaim(claims map[string]interface{}, names ...string) string {
	for _, name := range names {
		if value := stringClaim(claims, name); value != "" {
			return value
		}
	}
	return ""
}

func stringClaim(claims map[string]interface{}, name string) string {
	value, _ := claims[name].(string)
	return strings.TrimSpace(value)
}

func stringSliceClaim(claims map[string]interface{}, name string) []string {
	value, ok := claims[name]
	if !ok {
		return nil
	}
	switch typed := value.(type) {
	case string:
		if strings.Contains(typed, " ") {
			return strings.Fields(typed)
		}
		if typed != "" {
			return []string{typed}
		}
	case []interface{}:
		result := make([]string, 0, len(typed))
		for _, item := range typed {
			if text, ok := item.(string); ok && strings.TrimSpace(text) != "" {
				result = append(result, strings.TrimSpace(text))
			}
		}
		return result
	case []string:
		return typed
	}
	return nil
}

func collectRoles(claims map[string]interface{}, clientID, customClaim string) []string {
	seen := map[string]bool{}
	add := func(values ...string) {
		for _, value := range values {
			if normalized := normalizeRole(value); normalized != "" {
				seen[normalized] = true
			}
		}
	}
	add(stringSliceClaim(claims, customClaim)...)
	if realm, ok := claims["realm_access"].(map[string]interface{}); ok {
		add(stringSliceClaim(realm, "roles")...)
	}
	if resources, ok := claims["resource_access"].(map[string]interface{}); ok {
		if client, ok := resources[clientID].(map[string]interface{}); ok {
			add(stringSliceClaim(client, "roles")...)
		}
	}
	result := make([]string, 0, len(seen))
	for role := range seen {
		result = append(result, role)
	}
	sort.Strings(result)
	return result
}

func normalizeRole(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimPrefix(value, "kcsp-")
	replacer := strings.NewReplacer(" ", "_", "-", "_", ".", "_", "/", "_")
	return replacer.Replace(value)
}

var roleDisplayNames = map[string]string{
	"platform_super_admin":        "Platform Super Admin",
	"platform_administrator":      "Platform Super Admin",
	"tenant_admin":                "Tenant Admin",
	"mssp_manager":                "MSSP Manager",
	"soc_manager":                 "SOC Manager",
	"soc_l1":                      "SOC L1",
	"soc_l2":                      "SOC L2",
	"soc_l3":                      "SOC L3",
	"threat_hunter":               "Threat Hunter",
	"detection_engineer":          "Detection Engineer",
	"threat_intelligence_analyst": "Threat Intelligence Analyst",
	"soar_engineer":               "SOAR Engineer",
	"auditor":                     "Auditor",
	"collector":                   "Collector Service",
	"service_collector":           "Collector Service",
}

var rolePermissions = map[string][]string{
	"platform_super_admin":   {"*"},
	"platform_administrator": {"*"},
	"tenant_admin": {
		"platform.overview.read", "admin.users.manage", "admin.roles.manage", "admin.config.manage", "platform.audit.read",
		"platform.collectors.read", "platform.collectors.manage", "siem.parsers.read", "siem.parsers.write", "siem.parsers.publish", "siem.mitre.read", "soc.entities.read",
		"licenses.read", "licenses.install", "reports.read", "reports.generate",
		"siem.events.read", "siem.events.export", "siem.findings.read", "detection.rules.read", "siem.rules.read",
		"siem.hunt.read", "siem.hunt.execute", "siem.hunt.manage", "platform.retention.read", "platform.retention.manage", "ti.indicators.read", "ti.indicators.manage",
		"soc.alerts.read", "soc.alerts.manage", "soc.alerts.triage", "soc.incidents.read", "soc.incidents.create", "soc.incidents.manage",
		"soc.cases.manage", "soc.evidence.read", "soc.evidence.write", "soar.playbooks.read", "soar.playbooks.write", "soar.playbooks.execute", "soar.actions.approve", "soar.connectors.read", "soar.connectors.manage", "soar.connectors.test", "ueba.read", "ueba.feedback", "ai.read", "ai.request", "ai.decide", "ai.policy.manage",
	},
	"soc_manager": {
		"platform.overview.read", "platform.collectors.read", "siem.events.read", "siem.events.export", "siem.findings.read", "detection.rules.read", "siem.rules.read", "siem.parsers.read", "siem.mitre.read", "soc.entities.read",
		"licenses.read", "reports.read", "reports.generate",
		"siem.hunt.read", "siem.hunt.execute", "siem.hunt.manage", "platform.retention.read", "ti.indicators.read",
		"soc.alerts.read", "soc.alerts.manage", "soc.alerts.triage", "soc.incidents.read", "soc.incidents.create", "soc.incidents.manage",
		"soc.cases.manage", "soc.evidence.read", "soc.evidence.write", "soar.playbooks.read", "soar.playbooks.write", "soar.playbooks.execute", "soar.actions.approve", "soar.connectors.read", "soar.connectors.manage", "soar.connectors.test", "ueba.read", "ueba.feedback", "ai.read", "ai.request", "ai.decide",
	},
	"soc_l1": {
		"platform.overview.read", "platform.collectors.read", "siem.events.read", "siem.findings.read", "detection.rules.read", "siem.rules.read", "siem.parsers.read", "siem.mitre.read", "soc.entities.read",
		"licenses.read", "reports.read", "soc.cases.read", "soc.evidence.read", "soar.playbooks.read", "soar.connectors.read",
		"siem.hunt.read", "siem.hunt.execute", "siem.hunt.manage", "platform.retention.read", "ti.indicators.read",
		"soc.alerts.read", "soc.alerts.manage", "soc.alerts.triage", "soc.incidents.read", "soc.incidents.create", "ueba.read", "ai.read", "ai.request",
	},
	"soc_l2": {
		"platform.overview.read", "platform.collectors.read", "siem.events.read", "siem.events.export", "siem.findings.read", "detection.rules.read", "siem.rules.read", "siem.parsers.read", "siem.mitre.read", "soc.entities.read",
		"licenses.read", "reports.read", "reports.generate",
		"siem.hunt.read", "siem.hunt.execute", "siem.hunt.manage", "platform.retention.read", "ti.indicators.read",
		"soc.alerts.read", "soc.alerts.manage", "soc.alerts.triage", "soc.incidents.read", "soc.incidents.create", "soc.incidents.manage",
		"soc.cases.manage", "soc.evidence.read", "soc.evidence.write", "soar.playbooks.read", "soar.playbooks.execute", "soar.connectors.read", "platform.audit.read", "ueba.read", "ueba.feedback", "ai.read", "ai.request", "ai.decide",
	},
	"soc_l3": {
		"platform.overview.read", "platform.collectors.read", "siem.events.read", "siem.events.export", "siem.findings.read", "detection.rules.read", "siem.rules.read", "siem.parsers.read", "siem.mitre.read", "soc.entities.read",
		"licenses.read", "reports.read", "reports.generate",
		"siem.hunt.read", "siem.hunt.execute", "siem.hunt.manage", "platform.retention.read", "ti.indicators.read",
		"soc.alerts.read", "soc.alerts.manage", "soc.alerts.triage", "soc.incidents.read", "soc.incidents.create", "soc.incidents.manage",
		"soc.cases.manage", "soc.evidence.read", "soc.evidence.write", "soar.playbooks.read", "soar.playbooks.execute", "soar.actions.approve", "soar.connectors.read", "soar.connectors.test", "platform.audit.read", "ueba.read", "ueba.feedback", "ai.read", "ai.request", "ai.decide",
	},
	"threat_hunter": {
		"platform.overview.read", "siem.events.read", "siem.events.export", "siem.findings.read", "siem.rules.read", "siem.parsers.read", "siem.mitre.read", "soc.entities.read", "siem.hunt.read", "siem.hunt.execute", "siem.hunt.manage", "platform.retention.read", "ti.indicators.read",
		"soc.alerts.read", "soc.incidents.read", "soc.incidents.create", "soc.cases.manage", "soc.evidence.read", "soc.evidence.write", "ueba.read", "ueba.feedback", "ai.read", "ai.request", "ai.decide",
	},
	"detection_engineer": {
		"platform.overview.read", "platform.collectors.read", "siem.events.read", "siem.findings.read", "detection.rules.read", "siem.rules.read", "siem.rules.write", "siem.rules.publish", "siem.parsers.read", "siem.parsers.write", "siem.parsers.publish", "siem.mitre.read", "siem.hunt.read", "siem.hunt.execute", "platform.retention.read", "ti.indicators.read", "ueba.read", "ai.read", "ai.request",
	},
	"threat_intelligence_analyst": {
		"platform.overview.read", "siem.events.read", "soc.alerts.read", "soc.incidents.read", "ti.indicators.read", "ti.indicators.manage", "ai.read", "ai.request",
	},
	"soar_engineer": {
		"platform.overview.read", "soc.alerts.read", "soc.incidents.read", "soar.playbooks.read", "soar.playbooks.write", "soar.playbooks.execute", "soar.actions.approve", "soar.connectors.read", "soar.connectors.manage", "soar.connectors.test",
	},
	"auditor": {
		"platform.overview.read", "siem.events.read", "siem.rules.read", "siem.parsers.read", "siem.mitre.read", "soc.alerts.read", "soc.incidents.read", "soc.cases.read", "soc.evidence.read", "soc.entities.read", "platform.audit.read", "audit.read", "ti.indicators.read", "ueba.read", "ai.read", "licenses.read", "reports.read",
	},
	"mssp_manager": {
		"platform.overview.read", "soc.alerts.read", "soc.incidents.read", "platform.audit.read", "licenses.read", "reports.read", "mssp.tenants.read",
	},
	"collector":         {"siem.events.ingest", "platform.collectors.heartbeat"},
	"service_collector": {"siem.events.ingest", "platform.collectors.heartbeat"},
}

var permissionImplications = map[string][]string{
	"siem.events.export":         {"siem.events.read"},
	"platform.collectors.manage": {"platform.collectors.read"},
	"siem.rules.write":           {"siem.rules.read"},
	"siem.rules.publish":         {"siem.rules.write"},
	"siem.hunt.execute":          {"siem.hunt.read"},
	"siem.hunt.manage":           {"siem.hunt.read"},
	"platform.retention.manage":  {"platform.retention.read"},
	"soc.evidence.write":         {"soc.evidence.read"},
	"soc.cases.manage":           {"soc.cases.read"},
	"siem.parsers.write":         {"siem.parsers.read"},
	"siem.parsers.publish":       {"siem.parsers.write"},
	"reports.generate":           {"reports.read"},
	"licenses.install":           {"licenses.read"},
	"ti.indicators.manage":       {"ti.indicators.read"},
	"soc.alerts.manage":          {"soc.alerts.read"},
	"soc.alerts.triage":          {"soc.alerts.read"},
	"soc.incidents.create":       {"soc.incidents.read"},
	"soc.incidents.manage":       {"soc.incidents.read"},
	"soar.playbooks.write":       {"soar.playbooks.read"},
	"soar.playbooks.execute":     {"soar.playbooks.read"},
	"soar.connectors.manage":     {"soar.connectors.read"},
	"soar.connectors.test":       {"soar.connectors.read"},
	"ueba.feedback":              {"ueba.read"},
	"ai.request":                 {"ai.read"},
	"ai.decide":                  {"ai.read"},
	"ai.policy.manage":           {"ai.read"},
}

func grantPermission(permissions map[string]bool, permission string) {
	if permissions[permission] {
		return
	}
	permissions[permission] = true
	for _, implied := range permissionImplications[permission] {
		grantPermission(permissions, implied)
	}
}

var knownPermissions = func() map[string]bool {
	result := map[string]bool{}
	for _, permissions := range rolePermissions {
		for _, permission := range permissions {
			if permission != "*" {
				grantPermission(result, permission)
			}
		}
	}
	return result
}()

func permissionsForRoles(roles []string) (map[string]bool, []string, bool) {
	permissions := map[string]bool{"platform.session.read": true}
	displayNames := []string{}
	platformScope := false
	seenNames := map[string]bool{}
	for _, role := range roles {
		if role == "mssp_manager" {
			platformScope = true
		}
		for _, permission := range rolePermissions[role] {
			grantPermission(permissions, permission)
			if permission == "*" {
				platformScope = true
			}
		}
		if display := roleDisplayNames[role]; display != "" && !seenNames[display] {
			displayNames = append(displayNames, display)
			seenNames[display] = true
		}
	}
	sort.Strings(displayNames)
	return permissions, displayNames, platformScope
}
