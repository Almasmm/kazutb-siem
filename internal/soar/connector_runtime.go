package soar

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/kcsp/platform/internal/core"
)

type ConnectorTestRuntimeStore interface {
	ClaimSOARConnectorTest(context.Context, string, string, time.Duration) (core.SOARConnectorTestWorkItem, bool, error)
	FinishSOARConnectorTest(context.Context, string, string, string, string, string, string, int, int64) (core.SOARConnectorTest, error)
}

type ConnectorActionStore interface {
	GetSOARConnector(context.Context, string, string) (core.SOARConnector, error)
	ReserveSOARConnectorCall(context.Context, string, string, int, time.Time) error
}

type ConnectorTestResult struct {
	Status     string
	ErrorClass string
	Detail     string
	HTTPStatus int
	LatencyMS  int64
}

type ConnectorTester interface {
	TestConnector(context.Context, core.SOARConnector) (ConnectorTestResult, error)
}

type SecretResolver interface {
	Resolve(context.Context, string) (string, error)
}

type SecretResolutionError struct {
	Class  string
	Detail string
}

func (e *SecretResolutionError) Error() string { return e.Detail }

type EnvironmentSecretResolver struct{}

func (EnvironmentSecretResolver) Resolve(_ context.Context, reference string) (string, error) {
	if err := validateConnectorSecretRef(reference); err != nil {
		return "", &SecretResolutionError{Class: "SECRET_REF_INVALID", Detail: "secret binding is invalid"}
	}
	if !strings.HasPrefix(reference, "env://") {
		return "", &SecretResolutionError{
			Class:  "SECRET_PROVIDER_UNAVAILABLE",
			Detail: "configured secret provider is not available in this worker deployment",
		}
	}
	name := strings.Trim(strings.TrimPrefix(reference, "env://"), "/")
	value, ok := os.LookupEnv(name)
	if !ok || value == "" {
		return "", &SecretResolutionError{Class: "CREDENTIALS_REQUIRED", Detail: "bound connector credential is unavailable"}
	}
	return value, nil
}

type ManagedConnectorExecutor struct {
	store   ConnectorActionStore
	secrets SecretResolver
	client  *http.Client
}

func NewManagedConnectorExecutor(store ConnectorActionStore, secrets SecretResolver,
	client *http.Client) *ManagedConnectorExecutor {
	if secrets == nil {
		secrets = EnvironmentSecretResolver{}
	}
	return &ManagedConnectorExecutor{store: store, secrets: secrets, client: client}
}

func (e *ManagedConnectorExecutor) Execute(ctx context.Context, request ActionRequest) (ActionResult, error) {
	if request.Attempt.Mode == "DRY_RUN" || request.Attempt.ActionType == "kcsp.enrich.threat_intel" {
		return (SafeActionExecutor{}).Execute(ctx, request)
	}
	if e.store == nil {
		return ActionResult{}, &NodeError{
			Code: "connector_unavailable", Detail: "managed connector runtime is unavailable", Permanent: true,
		}
	}
	connector, err := e.store.GetSOARConnector(ctx, request.Attempt.TenantID, request.Attempt.ConnectorID)
	if err != nil {
		return ActionResult{}, &NodeError{
			Code: "connector_not_found", Detail: "configured connector is unavailable", Permanent: true,
		}
	}
	profile, profileExists := connectorProfileFor(connector.Kind)
	descriptor, actionExists := DefaultActionCatalog()[request.Attempt.ActionType]
	if !profileExists || !actionExists || !profile.Actions[request.Attempt.ActionType] ||
		descriptor.Level != request.Attempt.RiskLevel || descriptor.Level >= 6 {
		return ActionResult{}, &NodeError{
			Code: "connector_policy_denied", Detail: "connector kind and server-side action risk policy do not match", Permanent: true,
		}
	}
	if connector.State != core.SOARConnectorReady || connector.HealthStatus != core.SOARConnectorHealthHealthy {
		return ActionResult{}, &NodeError{
			Code: "connector_not_ready", Detail: "connector must pass a health test before LIVE execution", Permanent: true,
		}
	}
	if !connectorAllowsAction(connector, request.Attempt.ActionType) {
		return ActionResult{}, &NodeError{
			Code: "connector_action_denied", Detail: "action is not in the connector allowlist", Permanent: true,
		}
	}
	secret, nodeError := e.resolveActionSecret(ctx, connector)
	if nodeError != nil {
		return ActionResult{}, nodeError
	}
	if nodeError := validateResolvedConnectorAuthentication(connector, secret); nodeError != nil {
		return ActionResult{}, nodeError
	}
	payload, err := buildConnectorPayload(connector, request)
	if err != nil {
		return ActionResult{}, &NodeError{
			Code: "connector_payload_invalid", Detail: err.Error(), Permanent: true,
		}
	}
	if err := e.store.ReserveSOARConnectorCall(
		ctx, connector.TenantID, connector.ID, connector.RateLimitPerMinute, time.Now().UTC(),
	); err != nil {
		if errors.Is(err, ErrConnectorRateLimited) {
			return ActionResult{}, &NodeError{
				Code: "connector_rate_limited", Detail: "connector call quota is exhausted", Permanent: false,
			}
		}
		return ActionResult{}, err
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, connector.Endpoint, bytes.NewReader(payload))
	if err != nil {
		return ActionResult{}, &NodeError{
			Code: "connector_configuration", Detail: "connector endpoint is invalid", Permanent: true,
		}
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("User-Agent", "KCSP-SOAR-Connector/1.0")
	httpRequest.Header.Set("X-KCSP-Connector-ID", connector.ID)
	httpRequest.Header.Set("X-KCSP-Connector-Kind", connector.Kind)
	httpRequest.Header.Set("X-KCSP-Action", request.Attempt.ActionType)
	httpRequest.Header.Set("Idempotency-Key", request.Attempt.IdempotencyKey)
	applyConnectorAuthentication(httpRequest, connector, secret, payload)
	timeout := time.Duration(connector.TimeoutSeconds) * time.Second
	if timeout <= 0 || timeout > time.Minute {
		timeout = 10 * time.Second
	}
	client := e.client
	if client == nil {
		client = secureConnectorHTTPClient(timeout)
	}
	response, err := client.Do(httpRequest)
	if err != nil {
		class, detail := classifyConnectorHTTPError(err)
		permanent := class == "TLS" || class == "REDIRECT_FORBIDDEN" || class == "ENDPOINT_FORBIDDEN"
		return ActionResult{}, &NodeError{
			Code: "connector_" + strings.ToLower(class), Detail: detail, Permanent: permanent,
		}
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, (64<<10)+1))
	if err != nil {
		return ActionResult{}, &NodeError{
			Code: "connector_response_read", Detail: "connector response could not be read", Permanent: false,
		}
	}
	if len(body) > 64<<10 {
		return ActionResult{}, &NodeError{
			Code: "connector_response_too_large", Detail: "connector response exceeds 64 KiB", Permanent: true,
		}
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return ActionResult{}, connectorHTTPStatusError(response.StatusCode)
	}
	output := map[string]interface{}{
		"connector_id": connector.ID, "http_status": response.StatusCode, "acknowledged": true,
	}
	verification := "ACKNOWLEDGED"
	var responseObject map[string]interface{}
	if len(body) > 0 && json.Unmarshal(body, &responseObject) == nil {
		for _, key := range []string{"id", "ticket_id", "message_id", "action_id", "job_id", "incident_id"} {
			if value, ok := responseObject[key].(string); ok && len(value) <= 256 {
				output[key] = value
			}
		}
		if verified, _ := responseObject["verified"].(bool); verified {
			verification = "VERIFIED"
		}
	}
	return ActionResult{Output: output, VerificationStatus: verification}, nil
}

func (e *ManagedConnectorExecutor) TestConnector(ctx context.Context,
	connector core.SOARConnector) (ConnectorTestResult, error) {
	if connector.State == core.SOARConnectorDisabled {
		return ConnectorTestResult{
			Status: core.SOARConnectorTestFailed, ErrorClass: "DISABLED", Detail: "connector is disabled",
		}, nil
	}
	if _, ok := connectorProfileFor(connector.Kind); !ok {
		return ConnectorTestResult{
			Status: core.SOARConnectorTestFailed, ErrorClass: "CONFIGURATION", Detail: "connector kind has no runtime adapter",
		}, nil
	}
	var secret string
	if connector.AuthType != core.SOARConnectorAuthNone {
		if connector.SecretRef == "" {
			return ConnectorTestResult{
				Status: core.SOARConnectorTestCredentials, ErrorClass: "CREDENTIALS_REQUIRED",
				Detail: "connector has no secret binding",
			}, nil
		}
		resolved, err := e.secrets.Resolve(ctx, connector.SecretRef)
		if err != nil {
			var resolutionError *SecretResolutionError
			if errors.As(err, &resolutionError) {
				return ConnectorTestResult{
					Status: core.SOARConnectorTestCredentials, ErrorClass: resolutionError.Class,
					Detail: resolutionError.Detail,
				}, nil
			}
			return ConnectorTestResult{}, err
		}
		secret = resolved
	}
	if nodeError := validateResolvedConnectorAuthentication(connector, secret); nodeError != nil {
		return ConnectorTestResult{
			Status: core.SOARConnectorTestCredentials, ErrorClass: "CREDENTIALS_INVALID", Detail: nodeError.Detail,
		}, nil
	}
	endpoint, err := connectorHealthURL(connector)
	if err != nil {
		return ConnectorTestResult{
			Status: core.SOARConnectorTestFailed, ErrorClass: "CONFIGURATION", Detail: "health URL is invalid",
		}, nil
	}
	method, _ := connector.Settings["health_method"].(string)
	if method == "" {
		method = http.MethodHead
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), nil)
	if err != nil {
		return ConnectorTestResult{}, err
	}
	request.Header.Set("User-Agent", "KCSP-SOAR-Connector/1.0")
	request.Header.Set("X-KCSP-Connector-ID", connector.ID)
	switch connector.AuthType {
	case core.SOARConnectorAuthBearer:
		request.Header.Set("Authorization", "Bearer "+secret)
	case core.SOARConnectorAuthBasic:
		request.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(secret)))
	case core.SOARConnectorAuthAPIKey:
		request.Header.Set(connectorAPIKeyHeader(connector), secret)
	case core.SOARConnectorAuthHMAC:
		timestamp := strconv.FormatInt(time.Now().UTC().Unix(), 10)
		message := timestamp + "\n" + method + "\n" + endpoint.EscapedPath()
		mac := hmac.New(sha256.New, []byte(secret))
		_, _ = mac.Write([]byte(message))
		request.Header.Set("X-KCSP-Timestamp", timestamp)
		request.Header.Set("X-KCSP-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	timeout := time.Duration(connector.TimeoutSeconds) * time.Second
	if timeout <= 0 || timeout > time.Minute {
		timeout = 10 * time.Second
	}
	client := e.client
	if client == nil {
		client = secureConnectorHTTPClient(timeout)
	}
	started := time.Now()
	response, err := client.Do(request)
	latency := time.Since(started).Milliseconds()
	if err != nil {
		class, detail := classifyConnectorHTTPError(err)
		return ConnectorTestResult{
			Status: core.SOARConnectorTestFailed, ErrorClass: class, Detail: detail, LatencyMS: latency,
		}, nil
	}
	defer response.Body.Close()
	expected, _ := configInt(connector.Settings, "expected_status")
	if expected == 0 {
		expected = http.StatusOK
	}
	if response.StatusCode != expected {
		class := "PROTOCOL"
		switch {
		case response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden:
			class = "AUTHENTICATION"
		case response.StatusCode == http.StatusTooManyRequests:
			class = "RATE_LIMITED"
		case response.StatusCode >= 500:
			class = "UPSTREAM"
		}
		return ConnectorTestResult{
			Status: core.SOARConnectorTestFailed, ErrorClass: class,
			Detail:     fmt.Sprintf("health endpoint returned HTTP %d", response.StatusCode),
			HTTPStatus: response.StatusCode, LatencyMS: latency,
		}, nil
	}
	return ConnectorTestResult{
		Status:     core.SOARConnectorTestSucceeded,
		Detail:     fmt.Sprintf("health endpoint returned HTTP %d", response.StatusCode),
		HTTPStatus: response.StatusCode, LatencyMS: latency,
	}, nil
}

func (e *ManagedConnectorExecutor) resolveActionSecret(ctx context.Context,
	connector core.SOARConnector) (string, *NodeError) {
	if connector.AuthType == core.SOARConnectorAuthNone {
		return "", nil
	}
	if connector.SecretRef == "" {
		return "", &NodeError{
			Code: "connector_credentials_required", Detail: "connector has no secret binding", Permanent: true,
		}
	}
	secret, err := e.secrets.Resolve(ctx, connector.SecretRef)
	if err == nil {
		return secret, nil
	}
	return "", &NodeError{
		Code: "connector_credentials_required", Detail: "bound connector credential is unavailable", Permanent: true,
	}
}

func connectorAllowsAction(connector core.SOARConnector, action string) bool {
	for _, allowed := range connector.AllowedActions {
		if allowed == action {
			return true
		}
	}
	return false
}

func applyConnectorAuthentication(request *http.Request, connector core.SOARConnector, secret string, payload []byte) {
	switch connector.AuthType {
	case core.SOARConnectorAuthBearer:
		request.Header.Set("Authorization", "Bearer "+secret)
	case core.SOARConnectorAuthBasic:
		request.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(secret)))
	case core.SOARConnectorAuthAPIKey:
		request.Header.Set(connectorAPIKeyHeader(connector), secret)
	case core.SOARConnectorAuthHMAC:
		timestamp := strconv.FormatInt(time.Now().UTC().Unix(), 10)
		bodyHash := sha256.Sum256(payload)
		message := timestamp + "\n" + request.Method + "\n" + request.URL.EscapedPath() +
			"\n" + hex.EncodeToString(bodyHash[:])
		mac := hmac.New(sha256.New, []byte(secret))
		_, _ = mac.Write([]byte(message))
		request.Header.Set("X-KCSP-Timestamp", timestamp)
		request.Header.Set("X-KCSP-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
}

func validateResolvedConnectorAuthentication(connector core.SOARConnector, secret string) *NodeError {
	if connector.AuthType == core.SOARConnectorAuthNone {
		return nil
	}
	if secret == "" || len(secret) > 16<<10 {
		return &NodeError{Code: "connector_credentials_invalid", Detail: "connector credential is empty or exceeds safe bounds", Permanent: true}
	}
	if connector.AuthType == core.SOARConnectorAuthBasic {
		parts := strings.SplitN(secret, ":", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || parts[1] == "" {
			return &NodeError{Code: "connector_credentials_invalid", Detail: "BASIC credential must use a non-empty username:password value", Permanent: true}
		}
	}
	return nil
}

func connectorAPIKeyHeader(connector core.SOARConnector) string {
	if header, ok := connector.Settings["api_key_header"].(string); ok && header != "" {
		return header
	}
	return "X-API-Key"
}

func connectorHTTPStatusError(status int) *NodeError {
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return &NodeError{
			Code: "connector_authentication", Detail: fmt.Sprintf("connector returned HTTP %d", status), Permanent: true,
		}
	case status == http.StatusTooManyRequests:
		return &NodeError{
			Code: "connector_rate_limited", Detail: "connector returned HTTP 429", Permanent: false,
		}
	case status >= 500:
		return &NodeError{
			Code: "connector_upstream", Detail: fmt.Sprintf("connector returned HTTP %d", status), Permanent: false,
		}
	default:
		return &NodeError{
			Code: "connector_protocol", Detail: fmt.Sprintf("connector returned HTTP %d", status), Permanent: true,
		}
	}
}

func connectorHealthURL(connector core.SOARConnector) (*url.URL, error) {
	endpoint, err := url.Parse(connector.Endpoint)
	if err != nil {
		return nil, err
	}
	if path, ok := connector.Settings["health_path"].(string); ok && path != "" {
		endpoint.Path = path
		endpoint.RawPath = ""
	}
	return endpoint, nil
}

func secureConnectorHTTPClient(timeout time.Duration) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	dialer := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, errors.New("connector address is invalid")
		}
		addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, errors.New("connector host resolution failed")
		}
		for _, address := range addresses {
			ip := address.IP
			if ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() ||
				ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
				continue
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		}
		return nil, errors.New("connector host resolves only to forbidden addresses")
	}
	return &http.Client{
		Transport: transport, Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("connector redirects are forbidden")
		},
	}
}

func classifyConnectorHTTPError(err error) (string, string) {
	if errors.Is(err, context.DeadlineExceeded) {
		return "TIMEOUT", "connector request timed out"
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return "TIMEOUT", "connector request timed out"
	}
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "tls") || strings.Contains(message, "certificate") {
		return "TLS", "connector TLS validation failed"
	}
	if strings.Contains(message, "redirect") {
		return "REDIRECT_FORBIDDEN", "connector attempted an HTTP redirect"
	}
	if strings.Contains(message, "forbidden addresses") {
		return "ENDPOINT_FORBIDDEN", "connector endpoint resolved to a forbidden address"
	}
	return "NETWORK", "connector network request failed"
}
