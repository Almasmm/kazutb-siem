package soar

import (
	"context"
	"net"
	"strings"
	"testing"

	goldap "github.com/go-ldap/ldap/v3"
	"github.com/kcsp/platform/internal/core"
)

type recordingLDAPSession struct {
	baseDN     string
	targetDN   string
	account    string
	directory  string
	uac        string
	lockValue  string
	modifiedDN string
	lastFilter string
	closed     bool
}

func (s *recordingLDAPSession) Search(request *goldap.SearchRequest) (*goldap.SearchResult, error) {
	s.lastFilter = request.Filter
	if strings.EqualFold(request.BaseDN, s.baseDN) && request.Scope == goldap.ScopeBaseObject {
		return &goldap.SearchResult{Entries: []*goldap.Entry{goldap.NewEntry(s.baseDN, map[string][]string{"objectClass": {"domain"}})}}, nil
	}
	if !strings.EqualFold(request.BaseDN, s.targetDN) && request.Scope != goldap.ScopeWholeSubtree {
		return &goldap.SearchResult{}, nil
	}
	attributes := map[string][]string{"objectClass": {"person"}, "sAMAccountName": {s.account}, "uid": {s.account}}
	if s.directory == "ACTIVE_DIRECTORY" {
		attributes["userAccountControl"] = []string{s.uac}
	} else if s.lockValue != "" {
		attributes["pwdAccountLockedTime"] = []string{s.lockValue}
	}
	return &goldap.SearchResult{Entries: []*goldap.Entry{goldap.NewEntry(s.targetDN, attributes)}}, nil
}

func (s *recordingLDAPSession) Modify(request *goldap.ModifyRequest) error {
	s.modifiedDN = request.DN
	for _, change := range request.Changes {
		if change.Modification.Type == "userAccountControl" && len(change.Modification.Vals) == 1 {
			s.uac = change.Modification.Vals[0]
		}
		if change.Modification.Type == "pwdAccountLockedTime" {
			if len(change.Modification.Vals) == 0 {
				s.lockValue = ""
			} else {
				s.lockValue = change.Modification.Vals[0]
			}
		}
	}
	return nil
}

func (s *recordingLDAPSession) Close() error {
	s.closed = true
	return nil
}

func TestNormalizeLDAPConnectorRequiresScopedLDAPSContract(t *testing.T) {
	valid := ConnectorDraft{
		Name: "University Active Directory", Kind: core.SOARConnectorKindLDAPDirectory,
		Endpoint: "ldaps://dc01.example.edu:636", AuthType: core.SOARConnectorAuthBasic,
		SecretRef: "env://KCSP_CONNECTOR_SECRET_LDAP", AllowedActions: []string{"identity.disable_account", "identity.enable_account"},
		Settings: map[string]interface{}{"directory_type": "ACTIVE_DIRECTORY", "base_dn": "OU=Students,DC=example,DC=edu"},
	}
	connector, err := normalizeConnectorDraft(valid)
	if err != nil || connector.Settings["account_attribute"] != "sAMAccountName" {
		t.Fatalf("valid AD connector rejected: connector=%+v err=%v", connector, err)
	}
	invalid := []ConnectorDraft{
		func() ConnectorDraft { item := valid; item.Endpoint = "ldap://dc01.example.edu:389"; return item }(),
		func() ConnectorDraft { item := valid; item.AuthType = core.SOARConnectorAuthBearer; return item }(),
		func() ConnectorDraft {
			item := valid
			item.Settings = map[string]interface{}{"directory_type": "ACTIVE_DIRECTORY"}
			return item
		}(),
		func() ConnectorDraft {
			item := valid
			item.Settings = map[string]interface{}{"directory_type": "ACTIVE_DIRECTORY", "base_dn": "DC=example,DC=edu", "disabled_attribute": "userAccountControl"}
			return item
		}(),
	}
	for index, draft := range invalid {
		if _, err := normalizeConnectorDraft(draft); err == nil {
			t.Fatalf("invalid LDAP connector %d was accepted", index)
		}
	}
}

func TestManagedLDAPConnectorDisablesADAccountAndVerifiesState(t *testing.T) {
	t.Setenv("KCSP_CONNECTOR_SECRET_LDAP_TEST", "CN=KCSP Service,OU=Services,DC=example,DC=edu:directory-password")
	session := &recordingLDAPSession{
		baseDN: "OU=Students,DC=example,DC=edu", targetDN: "CN=Student One,OU=Students,DC=example,DC=edu",
		account: "student1", directory: "ACTIVE_DIRECTORY", uac: "512",
	}
	store := &typedConnectorRuntimeStore{connector: core.SOARConnector{
		ID: "ldap-1", TenantID: "tenant-a", Kind: core.SOARConnectorKindLDAPDirectory,
		State: core.SOARConnectorReady, HealthStatus: core.SOARConnectorHealthHealthy,
		Endpoint: "ldaps://dc01.example.edu:636", AuthType: core.SOARConnectorAuthBasic,
		SecretRef: "env://KCSP_CONNECTOR_SECRET_LDAP_TEST", AllowedActions: []string{"identity.disable_account", "identity.enable_account"},
		Settings: map[string]interface{}{
			"directory_type": "ACTIVE_DIRECTORY", "base_dn": session.baseDN, "account_attribute": "sAMAccountName",
		},
		TimeoutSeconds: 5, RateLimitPerMinute: 10,
	}}
	var resolvedSecret string
	executor := NewManagedConnectorExecutor(store, EnvironmentSecretResolver{}, nil)
	executor.ldapDial = func(_ context.Context, connector core.SOARConnector, secret string) (ldapConnectorSession, error) {
		if connector.Endpoint != "ldaps://dc01.example.edu:636" {
			t.Fatalf("unexpected LDAP endpoint %q", connector.Endpoint)
		}
		resolvedSecret = secret
		return session, nil
	}
	result, err := executor.Execute(context.Background(), ActionRequest{Attempt: core.SOARActionAttempt{
		TenantID: "tenant-a", ConnectorID: "ldap-1", ActionType: "identity.disable_account",
		RiskLevel: 4, Mode: "LIVE", IdempotencyKey: "exec-1|disable", ExecutionID: "exec-1",
		Request: map[string]interface{}{"account": "student1"},
	}})
	resultDN, _ := result.Output["distinguished_name"].(string)
	if err != nil || result.VerificationStatus != "VERIFIED" || !strings.EqualFold(resultDN, session.targetDN) {
		t.Fatalf("AD disable execution failed: result=%+v err=%v", result, err)
	}
	if session.uac != "514" || !strings.EqualFold(session.modifiedDN, session.targetDN) || store.reservations != 1 || resolvedSecret == "" || !session.closed {
		t.Fatalf("AD state contract failed: uac=%s modified=%s reservations=%d secret=%t closed=%v", session.uac, session.modifiedDN, store.reservations, resolvedSecret != "", session.closed)
	}
	if !strings.Contains(session.lastFilter, "objectClass") {
		t.Fatalf("unexpected LDAP search filter %q", session.lastFilter)
	}
}

func TestManagedLDAPConnectorEnablesGenericAccountByRemovingLock(t *testing.T) {
	session := &recordingLDAPSession{
		baseDN: "ou=people,dc=example,dc=edu", targetDN: "uid=student1,ou=people,dc=example,dc=edu",
		account: "student1", directory: "LDAP", lockValue: "000001010000Z",
	}
	connector := core.SOARConnector{Settings: map[string]interface{}{
		"directory_type": "LDAP", "base_dn": session.baseDN, "account_attribute": "uid",
		"disabled_attribute": "pwdAccountLockedTime", "disabled_value": "000001010000Z", "enabled_value": "",
	}}
	target, err := lookupLDAPConnectorTarget(session, connector, map[string]interface{}{"account": "student1"})
	if err != nil {
		t.Fatal(err)
	}
	modify, expected, err := ldapConnectorModifyRequest(connector, target, "identity.enable_account")
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Modify(modify); err != nil {
		t.Fatal(err)
	}
	if err := verifyLDAPConnectorState(session, connector, target.DN, "identity.enable_account", expected); err != nil {
		t.Fatal(err)
	}
	if session.lockValue != "" {
		t.Fatalf("generic LDAP lock attribute was not removed: %q", session.lockValue)
	}
}

func TestManagedLDAPConnectorHealthAndBoundary(t *testing.T) {
	t.Setenv("KCSP_CONNECTOR_SECRET_LDAP_HEALTH", "bind-user:bind-password")
	session := &recordingLDAPSession{baseDN: "DC=example,DC=edu", targetDN: "CN=User,DC=example,DC=edu", account: "user", directory: "ACTIVE_DIRECTORY", uac: "512"}
	executor := NewManagedConnectorExecutor(nil, EnvironmentSecretResolver{}, nil)
	executor.ldapDial = func(context.Context, core.SOARConnector, string) (ldapConnectorSession, error) { return session, nil }
	connector := core.SOARConnector{
		Kind: core.SOARConnectorKindLDAPDirectory, State: core.SOARConnectorCredentialsNeeded,
		Endpoint: "ldaps://dc01.example.edu:636", AuthType: core.SOARConnectorAuthBasic,
		SecretRef: "env://KCSP_CONNECTOR_SECRET_LDAP_HEALTH", TimeoutSeconds: 5,
		Settings: map[string]interface{}{"directory_type": "ACTIVE_DIRECTORY", "base_dn": session.baseDN, "account_attribute": "sAMAccountName"},
	}
	result, err := executor.TestConnector(context.Background(), connector)
	if err != nil || result.Status != core.SOARConnectorTestSucceeded {
		t.Fatalf("LDAP health contract failed: result=%+v err=%v", result, err)
	}
	if _, err := lookupLDAPConnectorTarget(session, connector, map[string]interface{}{"distinguished_name": "CN=Admin,DC=outside,DC=edu"}); err == nil {
		t.Fatal("out-of-base LDAP target was accepted")
	}
}

func TestLDAPErrorClassificationDoesNotExposeServerText(t *testing.T) {
	class, detail, permanent := classifyLDAPConnectorError(&goldap.Error{ResultCode: goldap.LDAPResultInvalidCredentials, Err: net.ErrClosed})
	if class != "AUTHENTICATION" || !permanent || strings.Contains(strings.ToLower(detail), "closed") {
		t.Fatalf("unsafe LDAP error classification: class=%s detail=%q permanent=%v", class, detail, permanent)
	}
}
