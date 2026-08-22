package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
)

type OIDCConfig struct {
	IssuerURL       string
	ClientID        string
	TenantClaim     string
	RolesClaim      string
	PermissionClaim string
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
			permissions[permission] = true
		}
	}
	for _, permission := range strings.Fields(stringClaim(claims, "scope")) {
		if knownPermissions[permission] {
			permissions[permission] = true
		}
	}
	tenants := map[string]bool{}
	for _, tenantID := range stringSliceClaim(claims, a.tenantClaim) {
		if tenantID = strings.TrimSpace(tenantID); tenantID != "" {
			tenants[tenantID] = true
		}
	}
	if tenantID := stringClaim(claims, "tenant_id"); tenantID != "" {
		tenants[tenantID] = true
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
	"soc_manager":                 "SOC Manager",
	"soc_l1":                      "SOC L1",
	"soc_l2":                      "SOC L2",
	"soc_l3":                      "SOC L3",
	"threat_hunter":               "Threat Hunter",
	"detection_engineer":          "Detection Engineer",
	"threat_intelligence_analyst": "Threat Intelligence Analyst",
	"auditor":                     "Auditor",
	"collector":                   "Collector Service",
	"service_collector":           "Collector Service",
}

var rolePermissions = map[string][]string{
	"platform_super_admin":   {"*"},
	"platform_administrator": {"*"},
	"tenant_admin": {
		"platform.overview.read", "admin.users.manage", "admin.roles.manage", "admin.config.manage", "platform.audit.read",
		"siem.events.read", "siem.events.export", "siem.findings.read", "detection.rules.read", "siem.rules.read",
		"soc.alerts.read", "soc.alerts.manage", "soc.alerts.triage", "soc.incidents.read", "soc.incidents.create", "soc.incidents.manage",
		"soc.cases.manage", "soc.evidence.read", "soc.evidence.write", "soar.playbooks.read", "soar.playbooks.execute",
	},
	"soc_manager": {
		"platform.overview.read", "siem.events.read", "siem.events.export", "siem.findings.read", "detection.rules.read",
		"soc.alerts.read", "soc.alerts.manage", "soc.alerts.triage", "soc.incidents.read", "soc.incidents.create", "soc.incidents.manage",
		"soc.cases.manage", "soc.evidence.read", "soc.evidence.write", "soar.playbooks.read", "soar.playbooks.execute", "soar.actions.approve",
	},
	"soc_l1": {
		"platform.overview.read", "siem.events.read", "siem.findings.read", "detection.rules.read",
		"soc.alerts.read", "soc.alerts.manage", "soc.alerts.triage", "soc.incidents.read", "soc.incidents.create",
	},
	"soc_l2": {
		"platform.overview.read", "siem.events.read", "siem.events.export", "siem.findings.read", "detection.rules.read",
		"soc.alerts.read", "soc.alerts.manage", "soc.alerts.triage", "soc.incidents.read", "soc.incidents.create", "soc.incidents.manage",
		"soc.cases.manage", "soc.evidence.read", "soc.evidence.write", "soar.playbooks.read", "soar.playbooks.execute", "platform.audit.read",
	},
	"soc_l3": {
		"platform.overview.read", "siem.events.read", "siem.events.export", "siem.findings.read", "detection.rules.read",
		"soc.alerts.read", "soc.alerts.manage", "soc.alerts.triage", "soc.incidents.read", "soc.incidents.create", "soc.incidents.manage",
		"soc.cases.manage", "soc.evidence.read", "soc.evidence.write", "soar.playbooks.read", "soar.playbooks.execute", "soar.actions.approve", "platform.audit.read",
	},
	"threat_hunter": {
		"platform.overview.read", "siem.events.read", "siem.events.export", "siem.findings.read", "siem.hunts.manage",
		"soc.alerts.read", "soc.incidents.read", "soc.incidents.create", "soc.cases.manage", "soc.evidence.read", "soc.evidence.write",
	},
	"detection_engineer": {
		"platform.overview.read", "siem.events.read", "siem.findings.read", "detection.rules.read", "siem.rules.read", "siem.rules.write", "siem.rules.publish",
	},
	"threat_intelligence_analyst": {
		"platform.overview.read", "siem.events.read", "soc.alerts.read", "soc.incidents.read", "ti.indicators.manage",
	},
	"auditor": {
		"platform.overview.read", "siem.events.read", "soc.alerts.read", "soc.incidents.read", "soc.evidence.read", "platform.audit.read", "audit.read",
	},
	"collector":         {"siem.events.ingest"},
	"service_collector": {"siem.events.ingest"},
}

var knownPermissions = func() map[string]bool {
	result := map[string]bool{}
	for _, permissions := range rolePermissions {
		for _, permission := range permissions {
			if permission != "*" {
				result[permission] = true
			}
		}
	}
	return result
}()

func permissionsForRoles(roles []string) (map[string]bool, []string, bool) {
	permissions := map[string]bool{}
	displayNames := []string{}
	platformScope := false
	seenNames := map[string]bool{}
	for _, role := range roles {
		for _, permission := range rolePermissions[role] {
			permissions[permission] = true
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
