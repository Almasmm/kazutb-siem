package soar

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"

	"github.com/kcsp/platform/internal/core"
)

type connectorProfile struct {
	SchemaVersion   string
	Actions         map[string]bool
	AllowAnonymous  bool
	EndpointSchemes map[string]bool
	AuthTypes       map[string]bool
}

var httpsConnectorSchemes = map[string]bool{"https": true}
var standardHTTPConnectorAuth = map[string]bool{
	core.SOARConnectorAuthBearer: true, core.SOARConnectorAuthHMAC: true,
	core.SOARConnectorAuthBasic: true, core.SOARConnectorAuthAPIKey: true,
}
var edrHTTPConnectorAuth = map[string]bool{
	core.SOARConnectorAuthBearer: true, core.SOARConnectorAuthHMAC: true,
	core.SOARConnectorAuthBasic: true, core.SOARConnectorAuthAPIKey: true,
	core.SOARConnectorAuthOAuth2ClientCredentials: true,
}
var webhookConnectorAuth = map[string]bool{
	core.SOARConnectorAuthNone: true, core.SOARConnectorAuthBearer: true,
	core.SOARConnectorAuthHMAC: true, core.SOARConnectorAuthBasic: true,
	core.SOARConnectorAuthAPIKey: true,
}

var connectorProfiles = map[string]connectorProfile{
	core.SOARConnectorKindWebhook: {
		SchemaVersion: "1.0", AllowAnonymous: true,
		Actions:         map[string]bool{"kcsp.ticket.create": true, "kcsp.notification.send": true},
		EndpointSchemes: httpsConnectorSchemes, AuthTypes: webhookConnectorAuth,
	},
	core.SOARConnectorKindFirewallREST: {
		SchemaVersion:   "kcsp.firewall.v1",
		Actions:         map[string]bool{"firewall.block_ip": true, "firewall.unblock_ip": true},
		EndpointSchemes: httpsConnectorSchemes, AuthTypes: standardHTTPConnectorAuth,
	},
	core.SOARConnectorKindITSMREST: {
		SchemaVersion: "kcsp.itsm.v1",
		Actions: map[string]bool{
			"kcsp.ticket.create": true, "kcsp.ticket.update": true,
			"kcsp.ticket.comment": true, "kcsp.ticket.close": true,
		},
		EndpointSchemes: httpsConnectorSchemes, AuthTypes: standardHTTPConnectorAuth,
	},
	core.SOARConnectorKindKCSPAPI: {
		SchemaVersion: "kcsp.internal.v1",
		Actions: map[string]bool{
			"kcsp.ticket.create": true, "kcsp.notification.send": true,
			"threat_intel.indicator.submit": true,
		},
		EndpointSchemes: httpsConnectorSchemes, AuthTypes: standardHTTPConnectorAuth,
	},
	core.SOARConnectorKindThreatIntelREST: {
		SchemaVersion:   "kcsp.threat-intel.v1",
		Actions:         map[string]bool{"threat_intel.indicator.submit": true},
		EndpointSchemes: httpsConnectorSchemes, AuthTypes: standardHTTPConnectorAuth,
	},
	core.SOARConnectorKindNotification: {
		SchemaVersion:   "kcsp.notification.v1",
		Actions:         map[string]bool{"kcsp.notification.send": true},
		EndpointSchemes: httpsConnectorSchemes, AuthTypes: standardHTTPConnectorAuth,
	},
	core.SOARConnectorKindEDRXDRREST: {
		SchemaVersion:   "kcsp.edr-xdr.v1",
		Actions:         map[string]bool{"endpoint.isolate": true, "endpoint.release": true},
		EndpointSchemes: httpsConnectorSchemes, AuthTypes: edrHTTPConnectorAuth,
	},
	core.SOARConnectorKindEmailSMTP: {
		SchemaVersion:   "kcsp.email.v1",
		Actions:         map[string]bool{"kcsp.notification.send": true},
		EndpointSchemes: map[string]bool{"smtps": true},
		AuthTypes:       map[string]bool{core.SOARConnectorAuthBasic: true},
	},
	core.SOARConnectorKindLDAPDirectory: {
		SchemaVersion:   "kcsp.ldap-directory.v1",
		Actions:         map[string]bool{"identity.disable_account": true, "identity.enable_account": true},
		EndpointSchemes: map[string]bool{"ldaps": true},
		AuthTypes:       map[string]bool{core.SOARConnectorAuthBasic: true},
	},
}

func connectorProfileFor(kind string) (connectorProfile, bool) {
	profile, ok := connectorProfiles[strings.ToUpper(strings.TrimSpace(kind))]
	return profile, ok
}

func buildConnectorPayload(connector core.SOARConnector, request ActionRequest) ([]byte, error) {
	profile, ok := connectorProfileFor(connector.Kind)
	if !ok || !profile.Actions[request.Attempt.ActionType] {
		return nil, fmt.Errorf("%w: action is unsupported by connector kind", ErrInvalidConnector)
	}
	metadata := map[string]interface{}{
		"idempotency_key": request.Attempt.IdempotencyKey,
		"execution_id":    request.Attempt.ExecutionID,
		"action_type":     request.Attempt.ActionType,
	}
	parameters := request.Attempt.Request
	if parameters == nil {
		parameters = map[string]interface{}{}
	}
	var payload map[string]interface{}
	switch connector.Kind {
	case core.SOARConnectorKindWebhook:
		payload = map[string]interface{}{
			"schema_version": profile.SchemaVersion, "action_type": request.Attempt.ActionType,
			"idempotency_key": request.Attempt.IdempotencyKey, "execution_id": request.Attempt.ExecutionID,
			"parameters": parameters,
		}
	case core.SOARConnectorKindITSMREST:
		operation := "create_ticket"
		payload = map[string]interface{}{
			"schema_version": profile.SchemaVersion, "fields": parameters, "kcsp": metadata,
		}
		switch request.Attempt.ActionType {
		case "kcsp.ticket.create":
			title, err := requiredConnectorParameter(parameters, "title", "summary")
			if err != nil {
				return nil, err
			}
			payload["title"] = title
		case "kcsp.ticket.update":
			operation = "update_ticket"
			reference, err := requiredConnectorParameter(parameters, "ticket_id", "ticket_key")
			if err != nil {
				return nil, err
			}
			payload["ticket_id"] = reference
		case "kcsp.ticket.comment":
			operation = "add_comment"
			reference, err := requiredConnectorParameter(parameters, "ticket_id", "ticket_key")
			if err != nil {
				return nil, err
			}
			comment, err := requiredConnectorParameter(parameters, "comment", "text", "message")
			if err != nil {
				return nil, err
			}
			payload["ticket_id"] = reference
			payload["comment"] = comment
		case "kcsp.ticket.close":
			operation = "close_ticket"
			reference, err := requiredConnectorParameter(parameters, "ticket_id", "ticket_key")
			if err != nil {
				return nil, err
			}
			payload["ticket_id"] = reference
		}
		payload["operation"] = operation
	case core.SOARConnectorKindNotification:
		text, err := requiredConnectorParameter(parameters, "text", "message")
		if err != nil {
			return nil, err
		}
		provider, _ := connector.Settings["provider"].(string)
		switch provider {
		case "SLACK", notificationProviderSlackWebAPI:
			payload = map[string]interface{}{"channel": connector.Settings["channel"], "text": text}
		case "TEAMS", notificationProviderTeamsGraph:
			payload = map[string]interface{}{"body": map[string]interface{}{"contentType": "text", "content": text}}
		default:
			payload = map[string]interface{}{
				"schema_version": profile.SchemaVersion, "operation": "send_message", "text": text,
				"message": parameters, "kcsp": metadata,
			}
		}
	case core.SOARConnectorKindFirewallREST:
		address, err := requiredConnectorParameter(parameters, "ip", "address")
		if err != nil {
			return nil, err
		}
		parsed, err := netip.ParseAddr(address)
		if err != nil || parsed.IsUnspecified() || parsed.IsMulticast() {
			return nil, fmt.Errorf("%w: firewall action requires a valid unicast IP address", ErrInvalidConnector)
		}
		operation := "block_ip"
		if request.Attempt.ActionType == "firewall.unblock_ip" {
			operation = "unblock_ip"
		}
		payload = map[string]interface{}{
			"schema_version": profile.SchemaVersion, "operation": operation, "target_ip": parsed.String(),
			"policy": parameters, "kcsp": metadata,
		}
	case core.SOARConnectorKindEDRXDRREST:
		endpointID, err := requiredConnectorParameter(parameters, "endpoint_id", "device_id")
		if err != nil {
			return nil, err
		}
		operation := "isolate_endpoint"
		if request.Attempt.ActionType == "endpoint.release" {
			operation = "release_endpoint"
		}
		payload = map[string]interface{}{
			"schema_version": profile.SchemaVersion, "operation": operation, "endpoint_id": endpointID,
			"request": parameters, "kcsp": metadata,
		}
	case core.SOARConnectorKindThreatIntelREST:
		indicator, err := requiredConnectorParameter(parameters, "indicator", "value")
		if err != nil {
			return nil, err
		}
		payload = map[string]interface{}{
			"schema_version": profile.SchemaVersion, "operation": "submit_indicator", "indicator": indicator,
			"record": parameters, "kcsp": metadata,
		}
	case core.SOARConnectorKindKCSPAPI:
		payload = map[string]interface{}{
			"schema_version": profile.SchemaVersion, "operation": request.Attempt.ActionType,
			"request": parameters, "kcsp": metadata,
		}
	case core.SOARConnectorKindEmailSMTP:
		to, err := requiredConnectorParameter(parameters, "to", "recipient")
		if err != nil {
			return nil, err
		}
		subject, err := requiredConnectorParameter(parameters, "subject", "title")
		if err != nil {
			return nil, err
		}
		body, err := requiredConnectorParameter(parameters, "body", "text", "message")
		if err != nil {
			return nil, err
		}
		payload = map[string]interface{}{
			"schema_version": profile.SchemaVersion, "operation": "send_email", "to": to,
			"subject": subject, "body": body, "kcsp": metadata,
		}
	case core.SOARConnectorKindLDAPDirectory:
		account, err := requiredConnectorParameter(parameters, "account", "user", "distinguished_name")
		if err != nil {
			return nil, err
		}
		operation := "disable_account"
		if request.Attempt.ActionType == "identity.enable_account" {
			operation = "enable_account"
		}
		payload = map[string]interface{}{
			"schema_version": profile.SchemaVersion, "operation": operation,
			"account": account, "request": parameters, "kcsp": metadata,
		}
	default:
		return nil, fmt.Errorf("%w: connector kind has no runtime adapter", ErrInvalidConnector)
	}
	encoded, err := json.Marshal(payload)
	if err != nil || len(encoded) > 1<<20 {
		return nil, fmt.Errorf("%w: connector action payload exceeds safe bounds", ErrInvalidConnector)
	}
	return encoded, nil
}

func requiredConnectorParameter(parameters map[string]interface{}, keys ...string) (string, error) {
	for _, key := range keys {
		if value, ok := parameters[key].(string); ok {
			value = strings.TrimSpace(value)
			if value != "" && len(value) <= 4096 {
				return value, nil
			}
		}
	}
	return "", fmt.Errorf("%w: connector action is missing a required string parameter", ErrInvalidConnector)
}
