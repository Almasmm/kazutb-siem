package soar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/kcsp/platform/internal/core"
)

const (
	edrXDRProviderGeneric           = "GENERIC"
	edrXDRProviderMicrosoftDefender = "MICROSOFT_DEFENDER_ENDPOINT"
	edrXDRProviderCrowdStrikeFalcon = "CROWDSTRIKE_FALCON"

	microsoftDefenderAPIHost = "api.security.microsoft.com"
	microsoftDefenderScope   = "https://api.securitycenter.microsoft.com/.default"
	maximumEDRResponseBytes  = 64 << 10
)

var (
	edrGUIDPattern      = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	mdeMachineIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{40,64}$`)
	falconAIDPattern    = regexp.MustCompile(`^[0-9a-fA-F]{32}$`)
	falconClientPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{8,128}$`)
	falconAPIHosts      = map[string]bool{
		"api.crowdstrike.com": true, "api.us-2.crowdstrike.com": true,
		"api.eu-1.crowdstrike.com": true, "api.laggar.gcw.crowdstrike.com": true,
		"api.us-gov-2.crowdstrike.mil": true,
	}
)

type connectorOAuthToken struct {
	Value     string
	ExpiresAt time.Time
}

type connectorOAuthTokenCache struct {
	mu      sync.Mutex
	entries map[string]connectorOAuthToken
}

func newConnectorOAuthTokenCache() *connectorOAuthTokenCache {
	return &connectorOAuthTokenCache{entries: map[string]connectorOAuthToken{}}
}

func (c *connectorOAuthTokenCache) get(key string, now time.Time) (string, bool) {
	if c == nil {
		return "", false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	token, ok := c.entries[key]
	return token.Value, ok && token.Value != "" && token.ExpiresAt.After(now.Add(time.Minute))
}

func (c *connectorOAuthTokenCache) put(key, value string, expiresAt time.Time) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = connectorOAuthToken{Value: value, ExpiresAt: expiresAt}
}

type edrOAuthCredentials struct {
	TenantID     string `json:"tenant_id"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	MemberCID    string `json:"member_cid,omitempty"`
}

type edrOAuthResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

func edrXDRProvider(connector core.SOARConnector) string {
	provider, _ := connector.Settings["provider"].(string)
	provider = strings.ToUpper(strings.TrimSpace(provider))
	if provider == "" {
		return edrXDRProviderGeneric
	}
	return provider
}

func isNativeEDRXDRProvider(connector core.SOARConnector) bool {
	provider := edrXDRProvider(connector)
	return provider == edrXDRProviderMicrosoftDefender || provider == edrXDRProviderCrowdStrikeFalcon
}

func validateNativeEDRConnectorConfiguration(kind, authType string, endpoint *url.URL,
	settings map[string]interface{}) error {
	if kind != core.SOARConnectorKindEDRXDRREST {
		return nil
	}
	provider, _ := settings["provider"].(string)
	if provider == "" || provider == edrXDRProviderGeneric {
		return nil
	}
	if authType != core.SOARConnectorAuthOAuth2ClientCredentials {
		return fmt.Errorf("%w: native EDR/XDR providers require OAUTH2_CLIENT_CREDENTIALS", ErrInvalidConnector)
	}
	if endpoint == nil || endpoint.Scheme != "https" || endpoint.Port() != "" ||
		(endpoint.Path != "" && endpoint.Path != "/") {
		return fmt.Errorf("%w: native EDR/XDR endpoint must be an allowlisted HTTPS origin", ErrInvalidConnector)
	}
	host := strings.ToLower(endpoint.Hostname())
	switch provider {
	case edrXDRProviderMicrosoftDefender:
		if host != microsoftDefenderAPIHost {
			return fmt.Errorf("%w: Microsoft Defender endpoint must use api.security.microsoft.com", ErrInvalidConnector)
		}
	case edrXDRProviderCrowdStrikeFalcon:
		if !falconAPIHosts[host] {
			return fmt.Errorf("%w: CrowdStrike endpoint must use a supported Falcon cloud", ErrInvalidConnector)
		}
	default:
		return fmt.Errorf("%w: native EDR/XDR provider is unsupported", ErrInvalidConnector)
	}
	return nil
}

func validateStoredNativeEDRConnector(connector core.SOARConnector) *NodeError {
	endpoint, err := url.Parse(connector.Endpoint)
	if err != nil || validateNativeEDRConnectorConfiguration(
		connector.Kind, connector.AuthType, endpoint, connector.Settings,
	) != nil {
		return &NodeError{Code: "connector_configuration", Detail: "native EDR/XDR provider configuration is invalid", Permanent: true}
	}
	return nil
}

func parseEDROAuthCredentials(provider, secret string) (edrOAuthCredentials, *NodeError) {
	var credentials edrOAuthCredentials
	decoder := json.NewDecoder(strings.NewReader(secret))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&credentials); err != nil {
		return credentials, invalidEDRCredentials()
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return credentials, invalidEDRCredentials()
	}
	credentials.TenantID = strings.TrimSpace(credentials.TenantID)
	credentials.ClientID = strings.TrimSpace(credentials.ClientID)
	credentials.MemberCID = strings.TrimSpace(credentials.MemberCID)
	if credentials.ClientSecret == "" || len(credentials.ClientSecret) > 4096 ||
		!utf8.ValidString(credentials.ClientSecret) || strings.ContainsRune(credentials.ClientSecret, '\x00') {
		return credentials, invalidEDRCredentials()
	}
	switch provider {
	case edrXDRProviderMicrosoftDefender:
		if !edrGUIDPattern.MatchString(credentials.TenantID) || !edrGUIDPattern.MatchString(credentials.ClientID) || credentials.MemberCID != "" {
			return credentials, invalidEDRCredentials()
		}
	case edrXDRProviderCrowdStrikeFalcon:
		if credentials.TenantID != "" || !falconClientPattern.MatchString(credentials.ClientID) ||
			(credentials.MemberCID != "" && !falconAIDPattern.MatchString(credentials.MemberCID)) {
			return credentials, invalidEDRCredentials()
		}
	default:
		return credentials, invalidEDRCredentials()
	}
	return credentials, nil
}

func invalidEDRCredentials() *NodeError {
	return &NodeError{Code: "connector_credentials_invalid", Detail: "native EDR/XDR OAuth credential document is invalid", Permanent: true}
}

func (e *ManagedConnectorExecutor) executeNativeEDRXDRConnector(ctx context.Context,
	connector core.SOARConnector, request ActionRequest, secret string) (ActionResult, error) {
	if nodeError := validateStoredNativeEDRConnector(connector); nodeError != nil {
		return ActionResult{}, nodeError
	}
	token, nodeError := e.nativeEDRAccessToken(ctx, connector, secret)
	if nodeError != nil {
		return ActionResult{}, nodeError
	}
	switch edrXDRProvider(connector) {
	case edrXDRProviderMicrosoftDefender:
		return e.executeMicrosoftDefenderAction(ctx, connector, request, token)
	case edrXDRProviderCrowdStrikeFalcon:
		return e.executeCrowdStrikeAction(ctx, connector, request, token)
	default:
		return ActionResult{}, &NodeError{Code: "connector_configuration", Detail: "native EDR/XDR provider is unsupported", Permanent: true}
	}
}

func (e *ManagedConnectorExecutor) nativeEDRAccessToken(ctx context.Context,
	connector core.SOARConnector, secret string) (string, *NodeError) {
	provider := edrXDRProvider(connector)
	digest := sha256.Sum256([]byte(provider + "\x00" + connector.Endpoint + "\x00" + secret))
	cacheKey := connector.ID + ":" + hex.EncodeToString(digest[:])
	if token, ok := e.oauthCache.get(cacheKey, time.Now().UTC()); ok {
		return token, nil
	}
	credentials, nodeError := parseEDROAuthCredentials(provider, secret)
	if nodeError != nil {
		return "", nodeError
	}
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {credentials.ClientID}, "client_secret": {credentials.ClientSecret}}
	tokenEndpoint := ""
	switch provider {
	case edrXDRProviderMicrosoftDefender:
		tokenEndpoint = "https://login.microsoftonline.com/" + url.PathEscape(credentials.TenantID) + "/oauth2/v2.0/token"
		form.Set("scope", microsoftDefenderScope)
	case edrXDRProviderCrowdStrikeFalcon:
		tokenEndpoint = strings.TrimRight(connector.Endpoint, "/") + "/oauth2/token"
		if credentials.MemberCID != "" {
			form.Set("member_cid", credentials.MemberCID)
		}
	default:
		return "", &NodeError{Code: "connector_configuration", Detail: "native EDR/XDR provider is unsupported", Permanent: true}
	}
	body, _, nodeError := e.nativeEDRRequest(ctx, connector, http.MethodPost, tokenEndpoint, "",
		"application/x-www-form-urlencoded", []byte(form.Encode()), nil)
	if nodeError != nil {
		return "", nodeError
	}
	var response edrOAuthResponse
	if json.Unmarshal(body, &response) != nil || response.AccessToken == "" || len(response.AccessToken) > 16<<10 ||
		(response.TokenType != "" && !strings.EqualFold(response.TokenType, "Bearer")) {
		return "", &NodeError{Code: "connector_protocol", Detail: "OAuth provider returned an invalid token response", Permanent: true}
	}
	if response.ExpiresIn < 120 || response.ExpiresIn > 86400 {
		response.ExpiresIn = 300
	}
	e.oauthCache.put(cacheKey, response.AccessToken, time.Now().UTC().Add(time.Duration(response.ExpiresIn)*time.Second))
	return response.AccessToken, nil
}

func (e *ManagedConnectorExecutor) executeMicrosoftDefenderAction(ctx context.Context,
	connector core.SOARConnector, request ActionRequest, token string) (ActionResult, error) {
	endpointID, err := requiredConnectorParameter(request.Attempt.Request, "endpoint_id", "device_id")
	if err != nil || !mdeMachineIDPattern.MatchString(endpointID) {
		return ActionResult{}, &NodeError{Code: "connector_payload_invalid", Detail: "Microsoft Defender action requires a valid machine ID", Permanent: true}
	}
	actionName := "isolate"
	payload := map[string]interface{}{"Comment": nativeEDRComment(request)}
	if request.Attempt.ActionType == "endpoint.isolate" {
		isolationType := nativeEDRParameter(request.Attempt.Request, "isolation_type")
		if isolationType == "" {
			isolationType = "Full"
		}
		if isolationType != "Full" && isolationType != "Selective" && isolationType != "UnManagedDevice" {
			return ActionResult{}, &NodeError{Code: "connector_payload_invalid", Detail: "Microsoft Defender isolation_type is invalid", Permanent: true}
		}
		payload["IsolationType"] = isolationType
	} else {
		actionName = "unisolate"
	}
	encoded, _ := json.Marshal(payload)
	target := strings.TrimRight(connector.Endpoint, "/") + "/api/machines/" + endpointID + "/" + actionName
	body, status, nodeError := e.nativeEDRRequest(ctx, connector, http.MethodPost, target, token,
		"application/json", encoded, map[string]string{"X-KCSP-Idempotency-Key": request.Attempt.IdempotencyKey})
	if nodeError != nil {
		return ActionResult{}, nodeError
	}
	var action struct {
		ID        string `json:"id"`
		Status    string `json:"status"`
		Type      string `json:"type"`
		MachineID string `json:"machineId"`
	}
	if json.Unmarshal(body, &action) != nil || action.ID == "" || len(action.ID) > 256 {
		return ActionResult{}, &NodeError{Code: "connector_protocol", Detail: "Microsoft Defender returned an invalid MachineAction", Permanent: true}
	}
	verifyTarget := strings.TrimRight(connector.Endpoint, "/") + "/api/machineactions/" + url.PathEscape(action.ID)
	verifiedBody, _, nodeError := e.nativeEDRRequest(ctx, connector, http.MethodGet, verifyTarget, token, "", nil, nil)
	if nodeError != nil {
		return ActionResult{}, nodeError
	}
	var verified struct {
		ID        string `json:"id"`
		Status    string `json:"status"`
		Type      string `json:"type"`
		MachineID string `json:"machineId"`
	}
	if json.Unmarshal(verifiedBody, &verified) != nil || verified.ID != action.ID {
		return ActionResult{}, &NodeError{Code: "connector_verification", Detail: "Microsoft Defender MachineAction verification failed", Permanent: false}
	}
	if strings.EqualFold(verified.Status, "Failed") || strings.EqualFold(verified.Status, "Cancelled") {
		return ActionResult{}, &NodeError{Code: "connector_provider_action_failed", Detail: "Microsoft Defender reported a failed MachineAction", Permanent: true}
	}
	verification := "ACKNOWLEDGED"
	if strings.EqualFold(verified.Status, "Succeeded") {
		verification = "VERIFIED"
	}
	return ActionResult{Output: map[string]interface{}{
		"connector_id": connector.ID, "provider": edrXDRProviderMicrosoftDefender,
		"action_id": verified.ID, "endpoint_id": endpointID, "provider_status": verified.Status,
		"http_status": status, "acknowledged": true,
	}, VerificationStatus: verification}, nil
}

func (e *ManagedConnectorExecutor) executeCrowdStrikeAction(ctx context.Context,
	connector core.SOARConnector, request ActionRequest, token string) (ActionResult, error) {
	endpointID, err := requiredConnectorParameter(request.Attempt.Request, "endpoint_id", "device_id")
	if err != nil || !falconAIDPattern.MatchString(endpointID) {
		return ActionResult{}, &NodeError{Code: "connector_payload_invalid", Detail: "CrowdStrike action requires a valid agent ID", Permanent: true}
	}
	actionName := "contain"
	if request.Attempt.ActionType == "endpoint.release" {
		actionName = "lift_containment"
	}
	encoded, _ := json.Marshal(map[string]interface{}{"ids": []string{endpointID}})
	target := strings.TrimRight(connector.Endpoint, "/") + "/devices/entities/devices-actions/v2?action_name=" + url.QueryEscape(actionName)
	body, status, nodeError := e.nativeEDRRequest(ctx, connector, http.MethodPost, target, token,
		"application/json", encoded, map[string]string{"X-KCSP-Idempotency-Key": request.Attempt.IdempotencyKey})
	if nodeError != nil {
		return ActionResult{}, nodeError
	}
	var actionResponse struct {
		Meta struct {
			TraceID string `json:"trace_id"`
		} `json:"meta"`
		Errors []json.RawMessage `json:"errors"`
	}
	if json.Unmarshal(body, &actionResponse) != nil || len(actionResponse.Errors) > 0 || len(actionResponse.Meta.TraceID) > 256 {
		return ActionResult{}, &NodeError{Code: "connector_protocol", Detail: "CrowdStrike returned an invalid action response", Permanent: true}
	}
	verifyPayload, _ := json.Marshal(map[string]interface{}{"ids": []string{endpointID}})
	verifyTarget := strings.TrimRight(connector.Endpoint, "/") + "/devices/entities/devices/v2"
	verifiedBody, _, nodeError := e.nativeEDRRequest(ctx, connector, http.MethodPost, verifyTarget, token,
		"application/json", verifyPayload, nil)
	if nodeError != nil {
		return ActionResult{}, nodeError
	}
	var verified struct {
		Resources []struct {
			DeviceID string `json:"device_id"`
			Status   string `json:"status"`
		} `json:"resources"`
		Errors []json.RawMessage `json:"errors"`
	}
	if json.Unmarshal(verifiedBody, &verified) != nil || len(verified.Errors) > 0 || len(verified.Resources) != 1 ||
		!strings.EqualFold(verified.Resources[0].DeviceID, endpointID) {
		return ActionResult{}, &NodeError{Code: "connector_verification", Detail: "CrowdStrike host verification failed", Permanent: false}
	}
	providerStatus := strings.ToLower(verified.Resources[0].Status)
	verification := "ACKNOWLEDGED"
	if (actionName == "contain" && providerStatus == "contained") ||
		(actionName == "lift_containment" && providerStatus == "normal") {
		verification = "VERIFIED"
	}
	output := map[string]interface{}{
		"connector_id": connector.ID, "provider": edrXDRProviderCrowdStrikeFalcon,
		"endpoint_id": endpointID, "provider_status": providerStatus, "http_status": status, "acknowledged": true,
	}
	if actionResponse.Meta.TraceID != "" {
		output["action_id"] = actionResponse.Meta.TraceID
	}
	return ActionResult{Output: output, VerificationStatus: verification}, nil
}

func (e *ManagedConnectorExecutor) testNativeEDRXDRConnector(ctx context.Context,
	connector core.SOARConnector, secret string) ConnectorTestResult {
	started := time.Now()
	if nodeError := validateStoredNativeEDRConnector(connector); nodeError != nil {
		return edrConnectorTestFailure(nodeError, 0, time.Since(started))
	}
	token, nodeError := e.nativeEDRAccessToken(ctx, connector, secret)
	if nodeError != nil {
		return edrConnectorTestFailure(nodeError, 0, time.Since(started))
	}
	target := ""
	switch edrXDRProvider(connector) {
	case edrXDRProviderMicrosoftDefender:
		target = strings.TrimRight(connector.Endpoint, "/") + "/api/machines?%24top=1"
	case edrXDRProviderCrowdStrikeFalcon:
		target = strings.TrimRight(connector.Endpoint, "/") + "/devices/queries/devices/v1?limit=1"
	}
	_, status, nodeError := e.nativeEDRRequest(ctx, connector, http.MethodGet, target, token, "", nil, nil)
	if nodeError != nil {
		return edrConnectorTestFailure(nodeError, status, time.Since(started))
	}
	return ConnectorTestResult{Status: core.SOARConnectorTestSucceeded,
		Detail: "native EDR/XDR OAuth and provider API checks succeeded", HTTPStatus: status,
		LatencyMS: time.Since(started).Milliseconds()}
}

func edrConnectorTestFailure(nodeError *NodeError, status int, elapsed time.Duration) ConnectorTestResult {
	errorClass := "PROTOCOL"
	switch nodeError.Code {
	case "connector_credentials_invalid", "connector_authentication":
		errorClass = "AUTHENTICATION"
	case "connector_configuration":
		errorClass = "CONFIGURATION"
	case "connector_rate_limited":
		errorClass = "RATE_LIMITED"
	case "connector_network", "connector_timeout", "connector_tls", "connector_endpoint_forbidden":
		errorClass = "NETWORK"
	case "connector_upstream":
		errorClass = "UPSTREAM"
	}
	return ConnectorTestResult{Status: core.SOARConnectorTestFailed, ErrorClass: errorClass,
		Detail: nodeError.Detail, HTTPStatus: status, LatencyMS: elapsed.Milliseconds()}
}

func (e *ManagedConnectorExecutor) nativeEDRRequest(ctx context.Context, connector core.SOARConnector,
	method, target, bearer, contentType string, payload []byte, headers map[string]string) ([]byte, int, *NodeError) {
	request, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(payload))
	if err != nil {
		return nil, 0, &NodeError{Code: "connector_configuration", Detail: "native EDR/XDR request URL is invalid", Permanent: true}
	}
	request.Header.Set("User-Agent", "KCSP-SOAR-EDR-Connector/1.0")
	request.Header.Set("Accept", "application/json")
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
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
	body, err := io.ReadAll(io.LimitReader(response.Body, maximumEDRResponseBytes+1))
	if err != nil {
		return nil, response.StatusCode, &NodeError{Code: "connector_response_read", Detail: "EDR/XDR response could not be read", Permanent: false}
	}
	if len(body) > maximumEDRResponseBytes {
		return nil, response.StatusCode, &NodeError{Code: "connector_response_too_large", Detail: "EDR/XDR response exceeds 64 KiB", Permanent: true}
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, response.StatusCode, connectorHTTPStatusError(response.StatusCode)
	}
	return body, response.StatusCode, nil
}

func nativeEDRComment(request ActionRequest) string {
	comment := nativeEDRParameter(request.Attempt.Request, "reason", "comment")
	if comment == "" {
		comment = "KCSP SOAR execution " + request.Attempt.ExecutionID
	}
	comment = strings.Map(func(r rune) rune {
		if r == '\x00' || r == '\r' || r == '\n' {
			return ' '
		}
		return r
	}, comment)
	if len(comment) > 1024 {
		comment = comment[:1024]
	}
	return comment
}

func nativeEDRParameter(parameters map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if value, ok := parameters[key].(string); ok {
			if value = strings.TrimSpace(value); value != "" {
				return value
			}
		}
	}
	return ""
}
