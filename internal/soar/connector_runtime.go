package soar

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
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
	secrets SecretResolver
	client  *http.Client
}

func NewManagedConnectorExecutor(secrets SecretResolver, client *http.Client) *ManagedConnectorExecutor {
	if secrets == nil {
		secrets = EnvironmentSecretResolver{}
	}
	return &ManagedConnectorExecutor{secrets: secrets, client: client}
}

func (e *ManagedConnectorExecutor) Execute(ctx context.Context, request ActionRequest) (ActionResult, error) {
	return (SafeActionExecutor{}).Execute(ctx, request)
}

func (e *ManagedConnectorExecutor) TestConnector(ctx context.Context,
	connector core.SOARConnector) (ConnectorTestResult, error) {
	if connector.State == core.SOARConnectorDisabled {
		return ConnectorTestResult{
			Status: core.SOARConnectorTestFailed, ErrorClass: "DISABLED", Detail: "connector is disabled",
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
