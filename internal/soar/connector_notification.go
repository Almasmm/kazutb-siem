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
	"strings"
	"time"

	"github.com/kcsp/platform/internal/core"
)

const (
	notificationProviderSlackWebAPI = "SLACK_WEB_API"
	notificationProviderTeamsGraph  = "TEAMS_GRAPH"
)

func isNativeNotificationProvider(connector core.SOARConnector) bool {
	provider := notificationProvider(connector)
	return provider == notificationProviderSlackWebAPI || provider == notificationProviderTeamsGraph
}

func notificationProvider(connector core.SOARConnector) string {
	provider, _ := connector.Settings["provider"].(string)
	return strings.ToUpper(strings.TrimSpace(provider))
}

func (e *ManagedConnectorExecutor) executeNativeNotificationConnector(ctx context.Context,
	connector core.SOARConnector, request ActionRequest, secret string) (ActionResult, error) {
	text, err := requiredConnectorParameter(request.Attempt.Request, "text", "message")
	if err != nil {
		return ActionResult{}, &NodeError{Code: "connector_payload_invalid", Detail: err.Error(), Permanent: true}
	}
	provider := notificationProvider(connector)
	if provider == notificationProviderSlackWebAPI {
		return e.executeSlackNotification(ctx, connector, request, secret, text)
	}
	if provider == notificationProviderTeamsGraph {
		return e.executeTeamsNotification(ctx, connector, request, secret, text)
	}
	return ActionResult{}, &NodeError{Code: "connector_configuration", Detail: "native notification provider is unsupported", Permanent: true}
}

func (e *ManagedConnectorExecutor) executeSlackNotification(ctx context.Context, connector core.SOARConnector,
	request ActionRequest, secret, text string) (ActionResult, error) {
	channel, _ := connector.Settings["channel"].(string)
	if !connectorSlackChannelID.MatchString(channel) {
		return ActionResult{}, &NodeError{Code: "connector_configuration", Detail: "Slack conversation ID is invalid", Permanent: true}
	}
	endpoint, err := nativeNotificationURL(connector, "/api/chat.postMessage")
	if err != nil {
		return ActionResult{}, err
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"channel": channel, "text": text, "client_msg_id": deterministicNotificationUUID(request.Attempt.IdempotencyKey),
	})
	body, status, nodeError := e.doNativeNotificationRequest(ctx, connector, secret, http.MethodPost,
		endpoint, payload, request.Attempt.ActionType, request.Attempt.IdempotencyKey)
	if nodeError != nil {
		return ActionResult{}, nodeError
	}
	var posted struct {
		OK      bool   `json:"ok"`
		Error   string `json:"error"`
		Channel string `json:"channel"`
		TS      string `json:"ts"`
	}
	if json.Unmarshal(body, &posted) != nil || !posted.OK || posted.TS == "" || posted.Channel == "" {
		return ActionResult{}, slackProtocolError(posted.Error)
	}
	verifyURL, err := nativeNotificationURL(connector, "/api/conversations.history")
	if err != nil {
		return ActionResult{}, err
	}
	query := verifyURL.Query()
	query.Set("channel", posted.Channel)
	query.Set("latest", posted.TS)
	query.Set("inclusive", "true")
	query.Set("limit", "1")
	verifyURL.RawQuery = query.Encode()
	verifiedBody, verifyStatus, verifyError := e.doNativeNotificationRequest(ctx, connector, secret,
		http.MethodGet, verifyURL, nil, request.Attempt.ActionType+".verify", request.Attempt.IdempotencyKey)
	if verifyError != nil {
		return ActionResult{}, &NodeError{Code: "connector_verification", Detail: "Slack acknowledged the message but read-after-write verification failed", Permanent: true}
	}
	var verified struct {
		OK       bool   `json:"ok"`
		Error    string `json:"error"`
		Messages []struct {
			TS string `json:"ts"`
		} `json:"messages"`
	}
	if json.Unmarshal(verifiedBody, &verified) != nil || !verified.OK || len(verified.Messages) != 1 || verified.Messages[0].TS != posted.TS {
		return ActionResult{}, &NodeError{Code: "connector_verification", Detail: "Slack message verification did not return the posted timestamp", Permanent: true}
	}
	return ActionResult{Output: map[string]interface{}{
		"connector_id": connector.ID, "provider": providerLabel(connector), "message_id": posted.TS,
		"channel_id": posted.Channel, "http_status": status, "verification_http_status": verifyStatus,
		"acknowledged": true,
	}, VerificationStatus: "VERIFIED"}, nil
}

func (e *ManagedConnectorExecutor) executeTeamsNotification(ctx context.Context, connector core.SOARConnector,
	request ActionRequest, secret, text string) (ActionResult, error) {
	teamID, _ := connector.Settings["team_id"].(string)
	channelID, _ := connector.Settings["channel_id"].(string)
	if !connectorTeamsTeamID.MatchString(teamID) || !connectorTeamsChannelID.MatchString(channelID) {
		return ActionResult{}, &NodeError{Code: "connector_configuration", Detail: "Teams team or channel ID is invalid", Permanent: true}
	}
	basePath := "/v1.0/teams/" + url.PathEscape(teamID) + "/channels/" + url.PathEscape(channelID) + "/messages"
	endpoint, err := nativeNotificationURL(connector, basePath)
	if err != nil {
		return ActionResult{}, err
	}
	payload, _ := json.Marshal(map[string]interface{}{"body": map[string]interface{}{"contentType": "text", "content": text}})
	body, status, nodeError := e.doNativeNotificationRequest(ctx, connector, secret, http.MethodPost,
		endpoint, payload, request.Attempt.ActionType, request.Attempt.IdempotencyKey)
	if nodeError != nil {
		return ActionResult{}, nodeError
	}
	var posted struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(body, &posted) != nil || posted.ID == "" || len(posted.ID) > 256 {
		return ActionResult{}, &NodeError{Code: "connector_protocol", Detail: "Teams Graph acknowledged the request without a message ID", Permanent: true}
	}
	verifyURL, err := nativeNotificationURL(connector, basePath+"/"+url.PathEscape(posted.ID))
	if err != nil {
		return ActionResult{}, err
	}
	verifiedBody, verifyStatus, verifyError := e.doNativeNotificationRequest(ctx, connector, secret,
		http.MethodGet, verifyURL, nil, request.Attempt.ActionType+".verify", request.Attempt.IdempotencyKey)
	if verifyError != nil {
		return ActionResult{}, &NodeError{Code: "connector_verification", Detail: "Teams Graph acknowledged the message but read-after-write verification failed", Permanent: true}
	}
	var verified struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(verifiedBody, &verified) != nil || verified.ID != posted.ID {
		return ActionResult{}, &NodeError{Code: "connector_verification", Detail: "Teams Graph verification returned a different message", Permanent: true}
	}
	return ActionResult{Output: map[string]interface{}{
		"connector_id": connector.ID, "provider": providerLabel(connector), "message_id": posted.ID,
		"team_id": teamID, "channel_id": channelID, "http_status": status,
		"verification_http_status": verifyStatus, "acknowledged": true,
	}, VerificationStatus: "VERIFIED"}, nil
}

func (e *ManagedConnectorExecutor) testNativeNotificationConnector(ctx context.Context,
	connector core.SOARConnector, secret string) ConnectorTestResult {
	provider := notificationProvider(connector)
	var endpoint *url.URL
	var err error
	if provider == notificationProviderSlackWebAPI {
		endpoint, err = nativeNotificationURL(connector, "/api/auth.test")
	} else {
		teamID, _ := connector.Settings["team_id"].(string)
		channelID, _ := connector.Settings["channel_id"].(string)
		if !connectorTeamsTeamID.MatchString(teamID) || !connectorTeamsChannelID.MatchString(channelID) {
			return ConnectorTestResult{Status: core.SOARConnectorTestFailed, ErrorClass: "CONFIGURATION", Detail: "Teams team or channel ID is invalid"}
		}
		endpoint, err = nativeNotificationURL(connector, "/v1.0/teams/"+url.PathEscape(teamID)+"/channels/"+url.PathEscape(channelID))
	}
	if err != nil {
		return ConnectorTestResult{Status: core.SOARConnectorTestFailed, ErrorClass: "CONFIGURATION", Detail: "native notification health URL is invalid"}
	}
	started := time.Now()
	body, status, nodeError := e.doNativeNotificationRequest(ctx, connector, secret, http.MethodGet,
		endpoint, nil, "kcsp.connector.health", "")
	latency := time.Since(started).Milliseconds()
	if nodeError != nil {
		return ConnectorTestResult{Status: core.SOARConnectorTestFailed,
			ErrorClass: strings.TrimPrefix(strings.ToUpper(nodeError.Code), "CONNECTOR_"), Detail: nodeError.Detail,
			HTTPStatus: status, LatencyMS: latency}
	}
	if provider == notificationProviderSlackWebAPI {
		var response struct {
			OK bool `json:"ok"`
		}
		if json.Unmarshal(body, &response) != nil || !response.OK {
			return ConnectorTestResult{Status: core.SOARConnectorTestFailed, ErrorClass: "PROTOCOL", Detail: "Slack auth.test returned an invalid response", HTTPStatus: status, LatencyMS: latency}
		}
	} else {
		var response struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(body, &response) != nil || response.ID == "" {
			return ConnectorTestResult{Status: core.SOARConnectorTestFailed, ErrorClass: "PROTOCOL", Detail: "Teams Graph channel lookup returned an invalid response", HTTPStatus: status, LatencyMS: latency}
		}
	}
	return ConnectorTestResult{Status: core.SOARConnectorTestSucceeded,
		Detail: provider + " API authentication succeeded", HTTPStatus: status, LatencyMS: latency}
}

func (e *ManagedConnectorExecutor) doNativeNotificationRequest(ctx context.Context, connector core.SOARConnector,
	secret, method string, endpoint *url.URL, payload []byte, action, idempotencyKey string) ([]byte, int, *NodeError) {
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), bytes.NewReader(payload))
	if err != nil {
		return nil, 0, &NodeError{Code: "connector_configuration", Detail: "notification request URL is invalid", Permanent: true}
	}
	request.Header.Set("Accept", "application/json")
	if len(payload) > 0 {
		request.Header.Set("Content-Type", "application/json; charset=utf-8")
	}
	request.Header.Set("User-Agent", "KCSP-SOAR-Notification-Connector/1.0")
	request.Header.Set("X-KCSP-Connector-ID", connector.ID)
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
		return nil, response.StatusCode, &NodeError{Code: "connector_response_read", Detail: "notification response could not be read", Permanent: false}
	}
	if len(body) > 64<<10 {
		return nil, response.StatusCode, &NodeError{Code: "connector_response_too_large", Detail: "notification response exceeds 64 KiB", Permanent: true}
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, response.StatusCode, connectorHTTPStatusError(response.StatusCode)
	}
	return body, response.StatusCode, nil
}

func nativeNotificationURL(connector core.SOARConnector, apiPath string) (*url.URL, error) {
	endpoint, err := url.Parse(connector.Endpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return nil, &NodeError{Code: "connector_configuration", Detail: "native notification endpoint is invalid", Permanent: true}
	}
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + apiPath
	endpoint.RawPath = ""
	return endpoint, nil
}

func slackProtocolError(providerCode string) *NodeError {
	switch providerCode {
	case "invalid_auth", "not_authed", "account_inactive", "token_revoked":
		return &NodeError{Code: "connector_authentication", Detail: "Slack rejected connector authentication", Permanent: true}
	case "ratelimited":
		return &NodeError{Code: "connector_rate_limited", Detail: "Slack rate limit was exceeded", Permanent: false}
	case "channel_not_found", "not_in_channel", "is_archived":
		return &NodeError{Code: "connector_protocol", Detail: "Slack conversation is unavailable to the connector", Permanent: true}
	default:
		return &NodeError{Code: "connector_protocol", Detail: "Slack returned an unsuccessful API response", Permanent: true}
	}
}

func deterministicNotificationUUID(value string) string {
	sum := sha256.Sum256([]byte(value))
	hexValue := hex.EncodeToString(sum[:16])
	return fmt.Sprintf("%s-%s-%s-%s-%s", hexValue[0:8], hexValue[8:12], hexValue[12:16], hexValue[16:20], hexValue[20:32])
}

func providerLabel(connector core.SOARConnector) string {
	return notificationProvider(connector)
}
