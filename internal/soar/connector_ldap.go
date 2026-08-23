package soar

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	goldap "github.com/go-ldap/ldap/v3"
	"github.com/kcsp/platform/internal/core"
)

type ldapConnectorSession interface {
	Search(*goldap.SearchRequest) (*goldap.SearchResult, error)
	Modify(*goldap.ModifyRequest) error
	Close() error
}

type ldapConnectorDialer func(context.Context, core.SOARConnector, string) (ldapConnectorSession, error)

type ldapConnectorTarget struct {
	DN      string
	Account string
	Entry   *goldap.Entry
}

func (e *ManagedConnectorExecutor) executeLDAPConnector(ctx context.Context, connector core.SOARConnector,
	request ActionRequest, secret string) (ActionResult, error) {
	session, err := e.openLDAPConnectorSession(ctx, connector, secret)
	if err != nil {
		return ActionResult{}, ldapConnectorNodeError(err)
	}
	defer session.Close()
	target, err := lookupLDAPConnectorTarget(session, connector, request.Attempt.Request)
	if err != nil {
		return ActionResult{}, ldapConnectorNodeError(err)
	}
	modify, expected, err := ldapConnectorModifyRequest(connector, target, request.Attempt.ActionType)
	if err != nil {
		return ActionResult{}, ldapConnectorNodeError(err)
	}
	if err := session.Modify(modify); err != nil {
		return ActionResult{}, ldapConnectorNodeError(err)
	}
	if err := verifyLDAPConnectorState(session, connector, target.DN, request.Attempt.ActionType, expected); err != nil {
		return ActionResult{}, &NodeError{
			Code: "connector_verification", Detail: "directory account state could not be verified after modification", Permanent: false,
		}
	}
	return ActionResult{
		Output: map[string]interface{}{
			"connector_id": connector.ID, "distinguished_name": target.DN, "account": target.Account,
			"directory_type": connectorSettingString(connector, "directory_type"), "modified": true,
		},
		VerificationStatus: "VERIFIED",
	}, nil
}

func (e *ManagedConnectorExecutor) testLDAPConnector(ctx context.Context, connector core.SOARConnector,
	secret string) ConnectorTestResult {
	started := time.Now()
	session, err := e.openLDAPConnectorSession(ctx, connector, secret)
	latency := time.Since(started).Milliseconds()
	if err != nil {
		class, detail, _ := classifyLDAPConnectorError(err)
		status := core.SOARConnectorTestFailed
		if class == "AUTHENTICATION" {
			status = core.SOARConnectorTestCredentials
		}
		return ConnectorTestResult{Status: status, ErrorClass: class, Detail: detail, LatencyMS: latency}
	}
	defer session.Close()
	baseDN := connectorSettingString(connector, "base_dn")
	result, err := session.Search(goldap.NewSearchRequest(
		baseDN, goldap.ScopeBaseObject, goldap.NeverDerefAliases, 1, 5, false,
		"(objectClass=*)", []string{"dn"}, nil,
	))
	latency = time.Since(started).Milliseconds()
	if err != nil || len(result.Entries) != 1 {
		if err == nil {
			err = errors.New("LDAP base object was not returned")
		}
		class, detail, _ := classifyLDAPConnectorError(err)
		return ConnectorTestResult{
			Status: core.SOARConnectorTestFailed, ErrorClass: class, Detail: detail, LatencyMS: latency,
		}
	}
	return ConnectorTestResult{
		Status: core.SOARConnectorTestSucceeded, Detail: "LDAPS bind and base DN search succeeded", LatencyMS: latency,
	}
}

func (e *ManagedConnectorExecutor) openLDAPConnectorSession(ctx context.Context,
	connector core.SOARConnector, secret string) (ldapConnectorSession, error) {
	if e.ldapDial != nil {
		return e.ldapDial(ctx, connector, secret)
	}
	return dialLDAPConnector(ctx, connector, secret)
}

func dialLDAPConnector(ctx context.Context, connector core.SOARConnector,
	secret string) (ldapConnectorSession, error) {
	endpoint, err := url.Parse(connector.Endpoint)
	if err != nil || !strings.EqualFold(endpoint.Scheme, "ldaps") || endpoint.Hostname() == "" {
		return nil, errors.New("LDAPS connector endpoint is invalid")
	}
	username, password, err := connectorBasicCredentials(secret)
	if err != nil {
		return nil, err
	}
	host := endpoint.Hostname()
	port := endpoint.Port()
	if port == "" {
		port = "636"
	}
	timeout := time.Duration(connector.TimeoutSeconds) * time.Second
	if timeout <= 0 || timeout > time.Minute {
		timeout = 10 * time.Second
	}
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, errors.New("connector host resolution failed")
	}
	foundAllowed := false
	var lastErr error
	for _, address := range addresses {
		ip := address.IP
		if ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			continue
		}
		foundAllowed = true
		dialer := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
		if deadline, ok := ctx.Deadline(); ok {
			dialer.Deadline = deadline
		}
		target := (&url.URL{Scheme: "ldaps", Host: net.JoinHostPort(ip.String(), port)}).String()
		connection, dialErr := goldap.DialURL(
			target,
			goldap.DialWithDialer(dialer),
			goldap.DialWithTLSConfig(&tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}),
		)
		if dialErr != nil {
			lastErr = dialErr
			continue
		}
		connection.SetTimeout(timeout)
		if bindErr := connection.Bind(username, password); bindErr != nil {
			connection.Close()
			return nil, bindErr
		}
		return connection, nil
	}
	if !foundAllowed {
		return nil, errors.New("connector host resolves only to forbidden addresses")
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, errors.New("connector network request failed")
}

func lookupLDAPConnectorTarget(session ldapConnectorSession, connector core.SOARConnector,
	parameters map[string]interface{}) (ldapConnectorTarget, error) {
	baseDN, err := goldap.ParseDN(connectorSettingString(connector, "base_dn"))
	if err != nil {
		return ldapConnectorTarget{}, errors.New("LDAP base DN is invalid")
	}
	accountAttribute := connectorSettingString(connector, "account_attribute")
	attributes := []string{accountAttribute}
	if connectorSettingString(connector, "directory_type") == "ACTIVE_DIRECTORY" {
		attributes = append(attributes, "userAccountControl")
	} else {
		attributes = append(attributes, connectorSettingString(connector, "disabled_attribute"))
	}
	if directDN, _ := parameters["distinguished_name"].(string); strings.TrimSpace(directDN) != "" {
		parsed, err := goldap.ParseDN(strings.TrimSpace(directDN))
		if err != nil || !(baseDN.EqualFold(parsed) || baseDN.AncestorOfFold(parsed)) {
			return ldapConnectorTarget{}, errors.New("directory target is outside the configured base DN")
		}
		result, err := session.Search(goldap.NewSearchRequest(
			parsed.String(), goldap.ScopeBaseObject, goldap.NeverDerefAliases, 1, 5, false,
			"(objectClass=*)", attributes, nil,
		))
		if err != nil || len(result.Entries) != 1 {
			return ldapConnectorTarget{}, errors.New("directory target was not found")
		}
		return ldapConnectorTarget{
			DN: parsed.String(), Account: result.Entries[0].GetAttributeValue(accountAttribute), Entry: result.Entries[0],
		}, nil
	}
	account, err := requiredConnectorParameter(parameters, "account", "user")
	if err != nil || len(account) > 512 {
		return ldapConnectorTarget{}, errors.New("directory account identifier is invalid")
	}
	filter := fmt.Sprintf("(&(%s=%s)(objectClass=*))", accountAttribute, goldap.EscapeFilter(account))
	result, err := session.Search(goldap.NewSearchRequest(
		baseDN.String(), goldap.ScopeWholeSubtree, goldap.NeverDerefAliases, 2, 5, false,
		filter, attributes, nil,
	))
	if err != nil {
		return ldapConnectorTarget{}, err
	}
	if len(result.Entries) != 1 {
		return ldapConnectorTarget{}, errors.New("directory account lookup must return exactly one entry")
	}
	targetDN, err := goldap.ParseDN(result.Entries[0].DN)
	if err != nil || !(baseDN.EqualFold(targetDN) || baseDN.AncestorOfFold(targetDN)) {
		return ldapConnectorTarget{}, errors.New("directory search returned an out-of-scope target")
	}
	return ldapConnectorTarget{DN: targetDN.String(), Account: account, Entry: result.Entries[0]}, nil
}

func ldapConnectorModifyRequest(connector core.SOARConnector, target ldapConnectorTarget,
	action string) (*goldap.ModifyRequest, string, error) {
	modify := goldap.NewModifyRequest(target.DN, nil)
	disabling := action == "identity.disable_account"
	if connectorSettingString(connector, "directory_type") == "ACTIVE_DIRECTORY" {
		current, err := strconv.ParseUint(target.Entry.GetAttributeValue("userAccountControl"), 10, 32)
		if err != nil {
			return nil, "", errors.New("Active Directory userAccountControl is missing or invalid")
		}
		if disabling {
			current |= 0x2
		} else {
			current &^= 0x2
		}
		expected := strconv.FormatUint(current, 10)
		modify.Replace("userAccountControl", []string{expected})
		return modify, expected, nil
	}
	attribute := connectorSettingString(connector, "disabled_attribute")
	expected := connectorSettingString(connector, "enabled_value")
	if disabling {
		expected = connectorSettingString(connector, "disabled_value")
		modify.Replace(attribute, []string{expected})
	} else if expected == "" {
		modify.Delete(attribute, nil)
	} else {
		modify.Replace(attribute, []string{expected})
	}
	return modify, expected, nil
}

func verifyLDAPConnectorState(session ldapConnectorSession, connector core.SOARConnector,
	targetDN, action, expected string) error {
	attribute := connectorSettingString(connector, "disabled_attribute")
	if connectorSettingString(connector, "directory_type") == "ACTIVE_DIRECTORY" {
		attribute = "userAccountControl"
	}
	result, err := session.Search(goldap.NewSearchRequest(
		targetDN, goldap.ScopeBaseObject, goldap.NeverDerefAliases, 1, 5, false,
		"(objectClass=*)", []string{attribute}, nil,
	))
	if err != nil || len(result.Entries) != 1 {
		return errors.New("directory verification lookup failed")
	}
	values := result.Entries[0].GetAttributeValues(attribute)
	if action == "identity.enable_account" && expected == "" {
		if len(values) == 0 {
			return nil
		}
		return errors.New("directory lock attribute remains present")
	}
	if len(values) == 1 && values[0] == expected {
		return nil
	}
	return errors.New("directory account state differs from requested state")
}

func connectorSettingString(connector core.SOARConnector, key string) string {
	value, _ := connector.Settings[key].(string)
	return strings.TrimSpace(value)
}

func ldapConnectorNodeError(err error) *NodeError {
	class, detail, permanent := classifyLDAPConnectorError(err)
	return &NodeError{Code: "connector_" + strings.ToLower(class), Detail: detail, Permanent: permanent}
}

func classifyLDAPConnectorError(err error) (string, string, bool) {
	if errors.Is(err, context.DeadlineExceeded) {
		return "TIMEOUT", "LDAP connector request timed out", false
	}
	var ldapError *goldap.Error
	if errors.As(err, &ldapError) {
		switch ldapError.ResultCode {
		case goldap.LDAPResultInvalidCredentials, goldap.LDAPResultStrongAuthRequired:
			return "AUTHENTICATION", fmt.Sprintf("LDAP authentication failed with result %d", ldapError.ResultCode), true
		case goldap.LDAPResultInsufficientAccessRights:
			return "AUTHORIZATION", "LDAP bind identity is not permitted to perform the operation", true
		case goldap.LDAPResultNoSuchObject:
			return "NOT_FOUND", "LDAP target does not exist", true
		case goldap.LDAPResultBusy, goldap.LDAPResultUnavailable, goldap.LDAPResultTimeLimitExceeded:
			return "UPSTREAM", fmt.Sprintf("LDAP service deferred the request with result %d", ldapError.ResultCode), false
		default:
			return "PROTOCOL", fmt.Sprintf("LDAP request failed with result %d", ldapError.ResultCode), true
		}
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return "TIMEOUT", "LDAP connector request timed out", false
	}
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "certificate") || strings.Contains(message, "tls") {
		return "TLS", "LDAP connector TLS validation failed", true
	}
	if strings.Contains(message, "forbidden addresses") || strings.Contains(message, "outside the configured base") || strings.Contains(message, "out-of-scope") {
		return "ENDPOINT_FORBIDDEN", "LDAP target is outside the configured directory boundary", true
	}
	if strings.Contains(message, "not found") || strings.Contains(message, "exactly one") {
		return "NOT_FOUND", "LDAP target was not found uniquely", true
	}
	if strings.Contains(message, "invalid") || strings.Contains(message, "missing") {
		return "CONFIGURATION", "LDAP connector configuration or target data is invalid", true
	}
	return "NETWORK", "LDAP connector network request failed", false
}
