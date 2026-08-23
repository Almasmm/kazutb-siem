package soar

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/kcsp/platform/internal/core"
)

const (
	itsmProviderGeneric    = "GENERIC"
	itsmProviderServiceNow = "SERVICENOW"
	itsmProviderJIRA       = "JIRA"
)

var serviceNowSysIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{32}$`)
var jiraIssueReferencePattern = regexp.MustCompile(`^(?:[A-Za-z][A-Za-z0-9_]{0,31}-[1-9][0-9]{0,18}|[0-9]{1,20})$`)

type itsmRequestPlan struct {
	Method    string
	Endpoint  *url.URL
	Payload   []byte
	Reference string
}

func itsmProvider(connector core.SOARConnector) string {
	provider, _ := connector.Settings["provider"].(string)
	provider = strings.ToUpper(strings.TrimSpace(provider))
	if provider == "" {
		return itsmProviderGeneric
	}
	return provider
}

func (e *ManagedConnectorExecutor) executeITSMConnector(ctx context.Context, connector core.SOARConnector,
	request ActionRequest, secret string) (ActionResult, error) {
	provider := itsmProvider(connector)
	plan, err := buildNativeITSMRequest(connector, request)
	if err != nil {
		return ActionResult{}, &NodeError{Code: "connector_payload_invalid", Detail: err.Error(), Permanent: true}
	}
	body, status, nodeError := e.doITSMRequest(ctx, connector, secret, plan.Method, plan.Endpoint,
		plan.Payload, request.Attempt.ActionType, request.Attempt.IdempotencyKey)
	if nodeError != nil {
		return ActionResult{}, nodeError
	}

	output := map[string]interface{}{
		"connector_id": connector.ID, "provider": provider, "http_status": status, "acknowledged": true,
	}
	reference := plan.Reference
	if request.Attempt.ActionType == "kcsp.ticket.create" {
		created, parseErr := parseITSMWriteResponse(provider, body)
		if parseErr != nil {
			return ActionResult{}, &NodeError{
				Code: "connector_protocol", Detail: "ITSM provider acknowledged the create request without a verifiable ticket identifier", Permanent: true,
			}
		}
		for key, value := range created {
			output[key] = value
		}
		if provider == itsmProviderServiceNow {
			reference, _ = created["ticket_id"].(string)
		} else {
			reference, _ = created["ticket_key"].(string)
			if reference == "" {
				reference, _ = created["ticket_id"].(string)
			}
		}
	} else if provider == itsmProviderServiceNow {
		output["ticket_id"] = reference
	} else {
		output["ticket_key"] = reference
	}

	verifyURL, err := nativeITSMVerificationURL(connector, reference)
	if err != nil {
		return ActionResult{}, &NodeError{Code: "connector_verification", Detail: "ITSM ticket reference cannot be verified safely", Permanent: true}
	}
	verifiedBody, verifyStatus, verifyError := e.doITSMRequest(ctx, connector, secret, http.MethodGet,
		verifyURL, nil, request.Attempt.ActionType+".verify", request.Attempt.IdempotencyKey)
	if verifyError != nil {
		return ActionResult{}, &NodeError{
			Code: "connector_verification", Detail: "ITSM write was acknowledged but read-after-write verification failed", Permanent: true,
		}
	}
	verified, err := parseITSMVerification(provider, reference, request.Attempt.ActionType, verifiedBody)
	if err != nil {
		return ActionResult{}, &NodeError{
			Code: "connector_verification", Detail: "ITSM write was acknowledged but the verified record did not match the ticket", Permanent: true,
		}
	}
	for key, value := range verified {
		output[key] = value
	}
	output["verification_http_status"] = verifyStatus
	return ActionResult{Output: output, VerificationStatus: "VERIFIED"}, nil
}

func (e *ManagedConnectorExecutor) testITSMConnector(ctx context.Context, connector core.SOARConnector,
	secret string) ConnectorTestResult {
	provider := itsmProvider(connector)
	endpoint, err := nativeITSMHealthURL(connector)
	if err != nil {
		return ConnectorTestResult{Status: core.SOARConnectorTestFailed, ErrorClass: "CONFIGURATION", Detail: "native ITSM health URL is invalid"}
	}
	started := time.Now()
	body, status, nodeError := e.doITSMRequest(ctx, connector, secret, http.MethodGet, endpoint, nil, "kcsp.connector.health", "")
	latency := time.Since(started).Milliseconds()
	if nodeError != nil {
		class := strings.TrimPrefix(strings.ToUpper(nodeError.Code), "CONNECTOR_")
		return ConnectorTestResult{Status: core.SOARConnectorTestFailed, ErrorClass: class, Detail: nodeError.Detail, HTTPStatus: status, LatencyMS: latency}
	}
	if len(body) == 0 || !json.Valid(body) {
		return ConnectorTestResult{Status: core.SOARConnectorTestFailed, ErrorClass: "PROTOCOL", Detail: "ITSM provider returned an invalid health response", HTTPStatus: status, LatencyMS: latency}
	}
	return ConnectorTestResult{
		Status: core.SOARConnectorTestSucceeded, Detail: provider + " API authentication succeeded",
		HTTPStatus: status, LatencyMS: latency,
	}
}

func buildNativeITSMRequest(connector core.SOARConnector, request ActionRequest) (itsmRequestPlan, error) {
	provider := itsmProvider(connector)
	parameters := request.Attempt.Request
	if parameters == nil {
		parameters = map[string]interface{}{}
	}
	if provider == itsmProviderServiceNow {
		return buildServiceNowRequest(connector, request, parameters)
	}
	if provider == itsmProviderJIRA {
		return buildJIRARequest(connector, request, parameters)
	}
	return itsmRequestPlan{}, fmt.Errorf("%w: native ITSM provider is unsupported", ErrInvalidConnector)
}

func buildServiceNowRequest(connector core.SOARConnector, request ActionRequest,
	parameters map[string]interface{}) (itsmRequestPlan, error) {
	plan := itsmRequestPlan{Method: http.MethodPatch}
	fields := map[string]interface{}{}
	switch request.Attempt.ActionType {
	case "kcsp.ticket.create":
		plan.Method = http.MethodPost
		title, err := requiredConnectorParameter(parameters, "title", "summary")
		if err != nil {
			return plan, err
		}
		fields["short_description"] = title
		fields["correlation_id"] = boundedITSMString(request.Attempt.IdempotencyKey, 100)
		if err := copyServiceNowFields(fields, parameters, true); err != nil {
			return plan, err
		}
		plan.Endpoint, err = nativeITSMURL(connector, "/api/now/table/incident")
		if err != nil {
			return plan, err
		}
	case "kcsp.ticket.update":
		reference, err := nativeITSMReference(itsmProviderServiceNow, parameters)
		if err != nil {
			return plan, err
		}
		plan.Reference = reference
		if err := copyServiceNowFields(fields, parameters, false); err != nil {
			return plan, err
		}
		if len(fields) == 0 {
			return plan, fmt.Errorf("%w: ServiceNow update requires at least one supported field", ErrInvalidConnector)
		}
		plan.Endpoint, err = nativeITSMURL(connector, "/api/now/table/incident/"+url.PathEscape(reference))
		if err != nil {
			return plan, err
		}
	case "kcsp.ticket.comment":
		reference, err := nativeITSMReference(itsmProviderServiceNow, parameters)
		if err != nil {
			return plan, err
		}
		comment, err := requiredConnectorParameter(parameters, "comment", "text", "message")
		if err != nil {
			return plan, err
		}
		plan.Reference = reference
		fields["work_notes"] = comment
		plan.Endpoint, err = nativeITSMURL(connector, "/api/now/table/incident/"+url.PathEscape(reference))
		if err != nil {
			return plan, err
		}
	case "kcsp.ticket.close":
		reference, err := nativeITSMReference(itsmProviderServiceNow, parameters)
		if err != nil {
			return plan, err
		}
		plan.Reference = reference
		reason, _, err := optionalITSMString(parameters, 4096, "reason", "close_notes", "comment")
		if err != nil {
			return plan, err
		}
		if reason == "" {
			reason = "Closed by KCSP SOAR"
		}
		fields["state"] = "7"
		fields["close_code"] = "Solved (Permanently)"
		fields["close_notes"] = reason
		plan.Endpoint, err = nativeITSMURL(connector, "/api/now/table/incident/"+url.PathEscape(reference))
		if err != nil {
			return plan, err
		}
	default:
		return plan, fmt.Errorf("%w: ServiceNow action is unsupported", ErrInvalidConnector)
	}
	encoded, err := marshalITSMBody(fields)
	if err != nil {
		return plan, err
	}
	plan.Payload = encoded
	return plan, nil
}

func buildJIRARequest(connector core.SOARConnector, request ActionRequest,
	parameters map[string]interface{}) (itsmRequestPlan, error) {
	plan := itsmRequestPlan{}
	projectKey, _ := connector.Settings["project_key"].(string)
	issueType, _ := connector.Settings["issue_type"].(string)
	if !connectorJIRAProjectKey.MatchString(projectKey) || strings.TrimSpace(issueType) == "" {
		return plan, fmt.Errorf("%w: Jira project and issue type are not configured", ErrInvalidConnector)
	}
	switch request.Attempt.ActionType {
	case "kcsp.ticket.create":
		title, err := requiredConnectorParameter(parameters, "title", "summary")
		if err != nil {
			return plan, err
		}
		fields := map[string]interface{}{
			"project": map[string]interface{}{"key": projectKey}, "issuetype": map[string]interface{}{"name": issueType},
			"summary": title,
		}
		if err := copyJIRAFields(fields, parameters, true); err != nil {
			return plan, err
		}
		plan.Method = http.MethodPost
		plan.Endpoint, err = nativeITSMURL(connector, "/rest/api/3/issue")
		if err != nil {
			return plan, err
		}
		plan.Payload, err = marshalITSMBody(map[string]interface{}{"fields": fields})
		return plan, err
	case "kcsp.ticket.update":
		reference, err := nativeITSMReference(itsmProviderJIRA, parameters)
		if err != nil {
			return plan, err
		}
		fields := map[string]interface{}{}
		if err := copyJIRAFields(fields, parameters, false); err != nil {
			return plan, err
		}
		if len(fields) == 0 {
			return plan, fmt.Errorf("%w: Jira update requires at least one supported field", ErrInvalidConnector)
		}
		plan.Method, plan.Reference = http.MethodPut, reference
		plan.Endpoint, err = nativeITSMURL(connector, "/rest/api/3/issue/"+url.PathEscape(reference))
		if err != nil {
			return plan, err
		}
		plan.Payload, err = marshalITSMBody(map[string]interface{}{"fields": fields})
		return plan, err
	case "kcsp.ticket.comment":
		reference, err := nativeITSMReference(itsmProviderJIRA, parameters)
		if err != nil {
			return plan, err
		}
		comment, err := requiredConnectorParameter(parameters, "comment", "text", "message")
		if err != nil {
			return plan, err
		}
		plan.Method, plan.Reference = http.MethodPost, reference
		plan.Endpoint, err = nativeITSMURL(connector, "/rest/api/3/issue/"+url.PathEscape(reference)+"/comment")
		if err != nil {
			return plan, err
		}
		plan.Payload, err = marshalITSMBody(map[string]interface{}{"body": jiraDocument(comment)})
		return plan, err
	case "kcsp.ticket.close":
		reference, err := nativeITSMReference(itsmProviderJIRA, parameters)
		if err != nil {
			return plan, err
		}
		transitionID, _ := connector.Settings["close_transition_id"].(string)
		if !connectorJIRATransitionID.MatchString(transitionID) {
			return plan, fmt.Errorf("%w: Jira close action requires close_transition_id", ErrInvalidConnector)
		}
		payload := map[string]interface{}{"transition": map[string]interface{}{"id": transitionID}}
		reason, present, err := optionalITSMString(parameters, 4096, "reason", "comment", "close_notes")
		if err != nil {
			return plan, err
		}
		if present {
			payload["update"] = map[string]interface{}{
				"comment": []interface{}{map[string]interface{}{"add": map[string]interface{}{"body": jiraDocument(reason)}}},
			}
		}
		plan.Method, plan.Reference = http.MethodPost, reference
		plan.Endpoint, err = nativeITSMURL(connector, "/rest/api/3/issue/"+url.PathEscape(reference)+"/transitions")
		if err != nil {
			return plan, err
		}
		plan.Payload, err = marshalITSMBody(payload)
		return plan, err
	default:
		return plan, fmt.Errorf("%w: Jira action is unsupported", ErrInvalidConnector)
	}
}

func copyServiceNowFields(destination, parameters map[string]interface{}, includeDescription bool) error {
	mappings := []struct {
		target string
		keys   []string
	}{
		{target: "short_description", keys: []string{"title", "summary"}},
		{target: "category", keys: []string{"category"}},
		{target: "subcategory", keys: []string{"subcategory"}},
		{target: "assignment_group", keys: []string{"assignment_group"}},
	}
	if includeDescription || destination["short_description"] == nil {
		mappings = append(mappings, struct {
			target string
			keys   []string
		}{target: "description", keys: []string{"description", "details"}})
	}
	for _, mapping := range mappings {
		value, present, err := optionalITSMString(parameters, 4096, mapping.keys...)
		if err != nil {
			return err
		}
		if present {
			destination[mapping.target] = value
		}
	}
	for _, key := range []string{"impact", "urgency"} {
		value, present, err := optionalITSMString(parameters, 1, key)
		if err != nil {
			return err
		}
		if present {
			if value != "1" && value != "2" && value != "3" {
				return fmt.Errorf("%w: ServiceNow %s must be 1, 2, or 3", ErrInvalidConnector, key)
			}
			destination[key] = value
		}
	}
	return nil
}

func copyJIRAFields(destination, parameters map[string]interface{}, includeDescription bool) error {
	if title, present, err := optionalITSMString(parameters, 4096, "title", "summary"); err != nil {
		return err
	} else if present {
		destination["summary"] = title
	}
	if includeDescription || destination["summary"] == nil {
		if description, present, err := optionalITSMString(parameters, 4096, "description", "details"); err != nil {
			return err
		} else if present {
			destination["description"] = jiraDocument(description)
		}
	}
	if priority, present, err := optionalITSMString(parameters, 120, "priority"); err != nil {
		return err
	} else if present {
		destination["priority"] = map[string]interface{}{"name": priority}
	}
	if labels, exists := parameters["labels"]; exists {
		values, ok := labels.([]interface{})
		if !ok || len(values) > 50 {
			return fmt.Errorf("%w: Jira labels must be an array with at most 50 values", ErrInvalidConnector)
		}
		normalized := make([]string, 0, len(values))
		for _, item := range values {
			value, ok := item.(string)
			value = strings.TrimSpace(value)
			if !ok || value == "" || len(value) > 255 || strings.ContainsAny(value, "\x00\r\n") {
				return fmt.Errorf("%w: Jira label is invalid", ErrInvalidConnector)
			}
			normalized = append(normalized, value)
		}
		destination["labels"] = normalized
	}
	return nil
}

func optionalITSMString(parameters map[string]interface{}, maximum int, keys ...string) (string, bool, error) {
	for _, key := range keys {
		value, exists := parameters[key]
		if !exists {
			continue
		}
		text, ok := value.(string)
		text = strings.TrimSpace(text)
		if !ok || text == "" || len(text) > maximum || strings.ContainsRune(text, '\x00') {
			return "", false, fmt.Errorf("%w: ITSM field %s is invalid", ErrInvalidConnector, key)
		}
		return text, true, nil
	}
	return "", false, nil
}

func nativeITSMReference(provider string, parameters map[string]interface{}) (string, error) {
	reference, err := requiredConnectorParameter(parameters, "ticket_id", "ticket_key")
	if err != nil {
		return "", err
	}
	if provider == itsmProviderServiceNow && !serviceNowSysIDPattern.MatchString(reference) {
		return "", fmt.Errorf("%w: ServiceNow actions require a 32-character sys_id", ErrInvalidConnector)
	}
	if provider == itsmProviderJIRA && !jiraIssueReferencePattern.MatchString(reference) {
		return "", fmt.Errorf("%w: Jira actions require an issue key or numeric ID", ErrInvalidConnector)
	}
	return reference, nil
}

func nativeITSMURL(connector core.SOARConnector, apiPath string) (*url.URL, error) {
	endpoint, err := url.Parse(connector.Endpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil {
		return nil, fmt.Errorf("%w: native ITSM endpoint is invalid", ErrInvalidConnector)
	}
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + apiPath
	endpoint.RawPath = ""
	endpoint.RawQuery = ""
	endpoint.Fragment = ""
	return endpoint, nil
}

func nativeITSMHealthURL(connector core.SOARConnector) (*url.URL, error) {
	provider := itsmProvider(connector)
	if provider == itsmProviderServiceNow {
		endpoint, err := nativeITSMURL(connector, "/api/now/table/incident")
		if err != nil {
			return nil, err
		}
		query := endpoint.Query()
		query.Set("sysparm_limit", "1")
		query.Set("sysparm_fields", "sys_id")
		endpoint.RawQuery = query.Encode()
		return endpoint, nil
	}
	if provider == itsmProviderJIRA {
		return nativeITSMURL(connector, "/rest/api/3/myself")
	}
	return nil, fmt.Errorf("%w: native ITSM provider is unsupported", ErrInvalidConnector)
}

func nativeITSMVerificationURL(connector core.SOARConnector, reference string) (*url.URL, error) {
	provider := itsmProvider(connector)
	if provider == itsmProviderServiceNow {
		if !serviceNowSysIDPattern.MatchString(reference) {
			return nil, fmt.Errorf("%w: ServiceNow sys_id is invalid", ErrInvalidConnector)
		}
		endpoint, err := nativeITSMURL(connector, "/api/now/table/incident/"+url.PathEscape(reference))
		if err != nil {
			return nil, err
		}
		query := endpoint.Query()
		query.Set("sysparm_fields", "sys_id,number,state,short_description,sys_updated_on")
		endpoint.RawQuery = query.Encode()
		return endpoint, nil
	}
	if provider == itsmProviderJIRA {
		if !jiraIssueReferencePattern.MatchString(reference) {
			return nil, fmt.Errorf("%w: Jira issue reference is invalid", ErrInvalidConnector)
		}
		endpoint, err := nativeITSMURL(connector, "/rest/api/3/issue/"+url.PathEscape(reference))
		if err != nil {
			return nil, err
		}
		query := endpoint.Query()
		query.Set("fields", "status,summary,updated")
		endpoint.RawQuery = query.Encode()
		return endpoint, nil
	}
	return nil, fmt.Errorf("%w: native ITSM provider is unsupported", ErrInvalidConnector)
}

func (e *ManagedConnectorExecutor) doITSMRequest(ctx context.Context, connector core.SOARConnector, secret,
	method string, endpoint *url.URL, payload []byte, action, idempotencyKey string) ([]byte, int, *NodeError) {
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), bytes.NewReader(payload))
	if err != nil {
		return nil, 0, &NodeError{Code: "connector_configuration", Detail: "ITSM request URL is invalid", Permanent: true}
	}
	request.Header.Set("Accept", "application/json")
	if len(payload) > 0 {
		request.Header.Set("Content-Type", "application/json")
	}
	request.Header.Set("User-Agent", "KCSP-SOAR-ITSM-Connector/1.0")
	request.Header.Set("X-KCSP-Connector-ID", connector.ID)
	request.Header.Set("X-KCSP-Connector-Kind", connector.Kind)
	request.Header.Set("X-KCSP-Action", action)
	if idempotencyKey != "" {
		request.Header.Set("Idempotency-Key", idempotencyKey)
	}
	applyConnectorAuthentication(request, connector, secret, payload)
	timeout := time.Duration(connector.TimeoutSeconds) * time.Second
	if timeout <= 0 || timeout > time.Minute {
		timeout = 10 * time.Second
	}
	client := e.client
	if client == nil {
		client = secureConnectorHTTPClient(timeout)
	}
	response, err := client.Do(request)
	if err != nil {
		class, detail := classifyConnectorHTTPError(err)
		permanent := class == "TLS" || class == "REDIRECT_FORBIDDEN" || class == "ENDPOINT_FORBIDDEN"
		return nil, 0, &NodeError{Code: "connector_" + strings.ToLower(class), Detail: detail, Permanent: permanent}
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, (64<<10)+1))
	if err != nil {
		return nil, response.StatusCode, &NodeError{Code: "connector_response_read", Detail: "ITSM response could not be read", Permanent: false}
	}
	if len(body) > 64<<10 {
		return nil, response.StatusCode, &NodeError{Code: "connector_response_too_large", Detail: "ITSM response exceeds 64 KiB", Permanent: true}
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, response.StatusCode, connectorHTTPStatusError(response.StatusCode)
	}
	return body, response.StatusCode, nil
}

func parseITSMWriteResponse(provider string, body []byte) (map[string]interface{}, error) {
	var envelope map[string]interface{}
	if len(body) == 0 || json.Unmarshal(body, &envelope) != nil {
		return nil, fmt.Errorf("invalid provider response")
	}
	output := map[string]interface{}{}
	if provider == itsmProviderServiceNow {
		result, ok := envelope["result"].(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("missing ServiceNow result")
		}
		sysID, _ := result["sys_id"].(string)
		if !serviceNowSysIDPattern.MatchString(sysID) {
			return nil, fmt.Errorf("missing ServiceNow sys_id")
		}
		output["ticket_id"] = sysID
		if number, ok := result["number"].(string); ok && len(number) <= 256 {
			output["ticket_key"] = number
		}
		return output, nil
	}
	if provider == itsmProviderJIRA {
		id, _ := envelope["id"].(string)
		key, _ := envelope["key"].(string)
		if !jiraIssueReferencePattern.MatchString(key) && !jiraIssueReferencePattern.MatchString(id) {
			return nil, fmt.Errorf("missing Jira issue identifier")
		}
		if id != "" && len(id) <= 256 {
			output["ticket_id"] = id
		}
		if key != "" && len(key) <= 256 {
			output["ticket_key"] = key
		}
		return output, nil
	}
	return nil, fmt.Errorf("unsupported provider")
}

func parseITSMVerification(provider, reference, action string, body []byte) (map[string]interface{}, error) {
	var envelope map[string]interface{}
	if len(body) == 0 || json.Unmarshal(body, &envelope) != nil {
		return nil, fmt.Errorf("invalid verification response")
	}
	output := map[string]interface{}{}
	if provider == itsmProviderServiceNow {
		result, ok := envelope["result"].(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("missing ServiceNow result")
		}
		sysID, _ := result["sys_id"].(string)
		if !strings.EqualFold(sysID, reference) {
			return nil, fmt.Errorf("ServiceNow record mismatch")
		}
		output["ticket_id"] = sysID
		if number, ok := result["number"].(string); ok && len(number) <= 256 {
			output["ticket_key"] = number
		}
		state := fmt.Sprint(result["state"])
		if action == "kcsp.ticket.close" && state != "7" && !strings.EqualFold(state, "closed") {
			return nil, fmt.Errorf("ServiceNow incident is not closed")
		}
		if state != "<nil>" && len(state) <= 120 {
			output["ticket_status"] = state
		}
		return output, nil
	}
	if provider == itsmProviderJIRA {
		id, _ := envelope["id"].(string)
		key, _ := envelope["key"].(string)
		if !strings.EqualFold(reference, id) && !strings.EqualFold(reference, key) {
			return nil, fmt.Errorf("Jira issue mismatch")
		}
		if id != "" && len(id) <= 256 {
			output["ticket_id"] = id
		}
		if key != "" && len(key) <= 256 {
			output["ticket_key"] = key
		}
		if fields, ok := envelope["fields"].(map[string]interface{}); ok {
			if status, ok := fields["status"].(map[string]interface{}); ok {
				if name, ok := status["name"].(string); ok && len(name) <= 120 {
					output["ticket_status"] = name
				}
			}
		}
		return output, nil
	}
	return nil, fmt.Errorf("unsupported provider")
}

func marshalITSMBody(payload map[string]interface{}) ([]byte, error) {
	encoded, err := json.Marshal(payload)
	if err != nil || len(encoded) > 1<<20 {
		return nil, fmt.Errorf("%w: native ITSM payload exceeds safe bounds", ErrInvalidConnector)
	}
	return encoded, nil
}

func jiraDocument(text string) map[string]interface{} {
	return map[string]interface{}{
		"type": "doc", "version": 1,
		"content": []interface{}{map[string]interface{}{
			"type": "paragraph", "content": []interface{}{map[string]interface{}{"type": "text", "text": text}},
		}},
	}
}

func boundedITSMString(value string, maximum int) string {
	value = strings.TrimSpace(value)
	if len(value) > maximum {
		return value[:maximum]
	}
	return value
}
