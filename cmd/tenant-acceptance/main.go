package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/kcsp/platform/internal/platform/tenant"
)

const acceptanceSchema = "kcsp.oidc-tenant-acceptance/v1"

var errAcceptanceFailed = errors.New("OIDC tenant-isolation acceptance failed")

type acceptanceConfig struct {
	BaseURL           *url.URL
	TenantA           string
	TenantB           string
	TokenA            string
	TokenB            string
	TenantClaim       string
	Endpoints         []string
	Client            *http.Client
	Now               func() time.Time
	AllowLoopbackHTTP bool
}

type oidcIdentity struct {
	Issuer  string
	Subject string
}

type acceptanceCheck struct {
	Name            string `json:"name"`
	Endpoint        string `json:"endpoint"`
	RequestedTenant string `json:"requested_tenant,omitempty"`
	ExpectedStatus  int    `json:"expected_status"`
	ActualStatus    int    `json:"actual_status"`
	ExpectedCode    string `json:"expected_code,omitempty"`
	ActualCode      string `json:"actual_code,omitempty"`
	Passed          bool   `json:"passed"`
	Error           string `json:"error,omitempty"`
}

type acceptanceReport struct {
	Schema           string            `json:"schema"`
	GeneratedAt      string            `json:"generated_at"`
	BaseURL          string            `json:"base_url"`
	OIDCIssuer       string            `json:"oidc_issuer,omitempty"`
	TenantA          string            `json:"tenant_a"`
	TenantB          string            `json:"tenant_b"`
	DistinctSubjects bool              `json:"distinct_subjects"`
	Passed           bool              `json:"passed"`
	Checks           []acceptanceCheck `json:"checks"`
	Failure          string            `json:"failure,omitempty"`
}

type problemDocument struct {
	Code string `json:"code"`
}

func main() {
	baseURL := flag.String("base-url", strings.TrimSpace(os.Getenv("KCSP_BASE_URL")), "KCSP HTTPS API base URL")
	tenantA := flag.String("tenant-a", strings.TrimSpace(os.Getenv("KCSP_TENANT_A")), "first canonical tenant ID")
	tenantB := flag.String("tenant-b", strings.TrimSpace(os.Getenv("KCSP_TENANT_B")), "second canonical tenant ID")
	tenantClaim := flag.String("tenant-claim", envOr("KCSP_OIDC_TENANT_CLAIM", "kcsp_tenants"), "OIDC tenant membership claim")
	endpoints := flag.String("endpoints", envOr("KCSP_ACCEPTANCE_ENDPOINTS", "/api/v1/overview,/api/v1/events?limit=1,/api/v1/alerts?limit=1,/api/v1/incidents?limit=1,/api/v1/cases?limit=1"), "comma-separated protected GET endpoints")
	reportPath := flag.String("report", strings.TrimSpace(os.Getenv("KCSP_ACCEPTANCE_REPORT")), "optional secret-free JSON report path")
	timeout := flag.Duration("timeout", durationEnv("KCSP_ACCEPTANCE_TIMEOUT", 15*time.Second), "per-request timeout")
	allowLoopbackHTTP := flag.Bool("allow-loopback-http", false, "allow plaintext only for an explicit loopback test endpoint")
	flag.Parse()

	parsedURL, parseError := url.Parse(strings.TrimSpace(*baseURL))
	config := acceptanceConfig{
		BaseURL: parsedURL, TenantA: strings.TrimSpace(*tenantA), TenantB: strings.TrimSpace(*tenantB),
		TokenA: strings.TrimSpace(os.Getenv("KCSP_OIDC_TOKEN_A")), TokenB: strings.TrimSpace(os.Getenv("KCSP_OIDC_TOKEN_B")),
		TenantClaim: strings.TrimSpace(*tenantClaim), Endpoints: splitEndpoints(*endpoints),
		Client: secureHTTPClient(*timeout), Now: time.Now, AllowLoopbackHTTP: *allowLoopbackHTTP,
	}
	report := newReport(config)
	var runError error
	if parseError != nil {
		runError = errors.New("base URL is invalid")
		report.Failure = runError.Error()
	} else {
		report, runError = runAcceptance(context.Background(), config)
	}

	body, marshalError := json.MarshalIndent(report, "", "  ")
	if marshalError != nil {
		fmt.Fprintln(os.Stderr, "encode acceptance report failed")
		os.Exit(2)
	}
	fmt.Println(string(body))
	if strings.TrimSpace(*reportPath) != "" {
		if err := writeReport(*reportPath, body); err != nil {
			fmt.Fprintln(os.Stderr, "write acceptance report failed")
			os.Exit(2)
		}
	}
	if runError != nil {
		fmt.Fprintln(os.Stderr, runError.Error())
		os.Exit(1)
	}
}

func runAcceptance(ctx context.Context, config acceptanceConfig) (acceptanceReport, error) {
	report := newReport(config)
	if err := validateConfig(config); err != nil {
		report.Failure = err.Error()
		return report, err
	}
	now := config.Now().UTC()
	identityA, err := parseOIDCIdentity(config.TokenA, config.TenantClaim, config.TenantA, config.TenantB, now)
	if err != nil {
		report.Failure = "first OIDC identity failed preflight"
		return report, errors.New(report.Failure)
	}
	identityB, err := parseOIDCIdentity(config.TokenB, config.TenantClaim, config.TenantB, config.TenantA, now)
	if err != nil {
		report.Failure = "second OIDC identity failed preflight"
		return report, errors.New(report.Failure)
	}
	if identityA.Issuer != identityB.Issuer {
		report.Failure = "OIDC identities use different issuers"
		return report, errors.New(report.Failure)
	}
	report.OIDCIssuer = identityA.Issuer
	report.DistinctSubjects = identityA.Subject != identityB.Subject
	if !report.DistinctSubjects {
		report.Failure = "OIDC identities must have distinct subjects"
		return report, errors.New(report.Failure)
	}

	identities := []struct {
		name   string
		token  string
		tenant string
		other  string
	}{
		{name: "identity_a", token: config.TokenA, tenant: config.TenantA, other: config.TenantB},
		{name: "identity_b", token: config.TokenB, tenant: config.TenantB, other: config.TenantA},
	}
	for _, identity := range identities {
		for _, endpoint := range config.Endpoints {
			report.Checks = append(report.Checks, performCheck(ctx, config, identity.name+"_own_access", identity.token, []string{identity.tenant}, endpoint, http.StatusOK, ""))
		}
		report.Checks = append(report.Checks,
			performCheck(ctx, config, identity.name+"_cross_tenant_denied", identity.token, []string{identity.other}, config.Endpoints[0], http.StatusForbidden, "tenant_denied"),
			performCheck(ctx, config, identity.name+"_missing_tenant_denied", identity.token, nil, config.Endpoints[0], http.StatusForbidden, "tenant_denied"),
			performCheck(ctx, config, identity.name+"_duplicate_tenant_denied", identity.token, []string{identity.tenant, identity.other}, config.Endpoints[0], http.StatusForbidden, "tenant_denied"),
		)
	}
	report.Passed = true
	for _, check := range report.Checks {
		if !check.Passed {
			report.Passed = false
			break
		}
	}
	if !report.Passed {
		report.Failure = errAcceptanceFailed.Error()
		return report, errAcceptanceFailed
	}
	return report, nil
}

func validateConfig(config acceptanceConfig) error {
	if config.BaseURL == nil || config.BaseURL.Scheme == "" || config.BaseURL.Host == "" || config.BaseURL.User != nil || config.BaseURL.RawQuery != "" || config.BaseURL.Fragment != "" {
		return errors.New("base URL must be an absolute origin without credentials, query, or fragment")
	}
	if config.BaseURL.Path != "" && config.BaseURL.Path != "/" {
		return errors.New("base URL must not contain an application path")
	}
	if config.BaseURL.Scheme != "https" {
		if config.BaseURL.Scheme != "http" || !config.AllowLoopbackHTTP || !isLoopback(config.BaseURL.Hostname()) {
			return errors.New("acceptance requires HTTPS; plaintext is restricted to an explicitly enabled loopback endpoint")
		}
	}
	if err := tenant.Validate(config.TenantA); err != nil {
		return errors.New("first tenant ID is invalid")
	}
	if err := tenant.Validate(config.TenantB); err != nil {
		return errors.New("second tenant ID is invalid")
	}
	if config.TenantA == config.TenantB {
		return errors.New("two distinct tenant IDs are required")
	}
	if config.TokenA == "" || config.TokenB == "" || config.TokenA == config.TokenB {
		return errors.New("two distinct OIDC tokens are required through KCSP_OIDC_TOKEN_A and KCSP_OIDC_TOKEN_B")
	}
	if config.TenantClaim == "" || strings.ContainsAny(config.TenantClaim, "\r\n") {
		return errors.New("OIDC tenant claim is invalid")
	}
	if len(config.Endpoints) == 0 {
		return errors.New("at least one protected endpoint is required")
	}
	for _, endpoint := range config.Endpoints {
		parsed, err := url.ParseRequestURI(endpoint)
		if err != nil || parsed.IsAbs() || !strings.HasPrefix(parsed.Path, "/api/v1/") || strings.ContainsAny(endpoint, "\r\n") {
			return errors.New("acceptance endpoints must be relative protected /api/v1 paths")
		}
	}
	if config.Client == nil || config.Now == nil {
		return errors.New("acceptance runtime is incomplete")
	}
	return nil
}

func parseOIDCIdentity(tokenValue, tenantClaim, expectedTenant, forbiddenTenant string, now time.Time) (oidcIdentity, error) {
	parts := strings.Split(tokenValue, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return oidcIdentity{}, errors.New("token is not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return oidcIdentity{}, errors.New("JWT payload is invalid")
	}
	claims := map[string]interface{}{}
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.UseNumber()
	if err := decoder.Decode(&claims); err != nil {
		return oidcIdentity{}, errors.New("JWT claims are invalid")
	}
	issuer := claimString(claims["iss"])
	subject := claimString(claims["sub"])
	issuerURL, err := url.Parse(issuer)
	if err != nil || issuerURL.Scheme != "https" || issuerURL.Host == "" || subject == "" {
		return oidcIdentity{}, errors.New("JWT issuer or subject is invalid")
	}
	expires, err := claimUnixTime(claims["exp"])
	if err != nil || !expires.After(now) {
		return oidcIdentity{}, errors.New("JWT is expired or has no valid expiry")
	}
	memberships, err := tenantMemberships(claims, tenantClaim)
	if err != nil || len(memberships) != 1 || !memberships[expectedTenant] || memberships[forbiddenTenant] {
		return oidcIdentity{}, errors.New("JWT must contain exactly the expected tenant membership")
	}
	return oidcIdentity{Issuer: issuerURL.String(), Subject: subject}, nil
}

func tenantMemberships(claims map[string]interface{}, tenantClaim string) (map[string]bool, error) {
	result := map[string]bool{}
	add := func(value string) error {
		value = strings.TrimSpace(value)
		if err := tenant.Validate(value); err != nil {
			return err
		}
		result[value] = true
		return nil
	}
	appendClaim := func(value interface{}) error {
		switch typed := value.(type) {
		case nil:
			return nil
		case string:
			return add(typed)
		case []interface{}:
			for _, item := range typed {
				text, ok := item.(string)
				if !ok || add(text) != nil {
					return errors.New("tenant membership claim is invalid")
				}
			}
			return nil
		default:
			return errors.New("tenant membership claim is invalid")
		}
	}
	if err := appendClaim(claims[tenantClaim]); err != nil {
		return nil, err
	}
	if tenantClaim != "tenant_id" {
		if err := appendClaim(claims["tenant_id"]); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func performCheck(ctx context.Context, config acceptanceConfig, name, tokenValue string, tenantHeaders []string, endpoint string, expectedStatus int, expectedCode string) acceptanceCheck {
	check := acceptanceCheck{Name: name, Endpoint: endpoint, ExpectedStatus: expectedStatus, ExpectedCode: expectedCode}
	if len(tenantHeaders) == 1 {
		check.RequestedTenant = tenantHeaders[0]
	}
	target := config.BaseURL.ResolveReference(&url.URL{Path: endpointPath(endpoint), RawQuery: endpointQuery(endpoint)})
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		check.Error = "request construction failed"
		return check
	}
	request.Header.Set("Authorization", "Bearer "+tokenValue)
	request.Header.Set("User-Agent", "kcsp-tenant-acceptance/1.0")
	for _, tenantID := range tenantHeaders {
		request.Header.Add("X-KCSP-Tenant-ID", tenantID)
	}
	response, err := config.Client.Do(request)
	if err != nil {
		check.Error = "request failed"
		return check
	}
	defer response.Body.Close()
	check.ActualStatus = response.StatusCode
	limited, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	var problem problemDocument
	if json.Unmarshal(limited, &problem) == nil {
		check.ActualCode = problem.Code
	}
	check.Passed = check.ActualStatus == expectedStatus && (expectedCode == "" || check.ActualCode == expectedCode)
	return check
}

func secureHTTPClient(timeout time.Duration) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func newReport(config acceptanceConfig) acceptanceReport {
	baseURL := ""
	if config.BaseURL != nil {
		baseURL = config.BaseURL.String()
	}
	now := time.Now().UTC()
	if config.Now != nil {
		now = config.Now().UTC()
	}
	return acceptanceReport{
		Schema: acceptanceSchema, GeneratedAt: now.Format(time.RFC3339Nano), BaseURL: baseURL,
		TenantA: config.TenantA, TenantB: config.TenantB, Checks: []acceptanceCheck{},
	}
}

func splitEndpoints(value string) []string {
	result := []string{}
	for _, endpoint := range strings.Split(value, ",") {
		if endpoint = strings.TrimSpace(endpoint); endpoint != "" {
			result = append(result, endpoint)
		}
	}
	return result
}

func endpointPath(endpoint string) string {
	parsed, _ := url.ParseRequestURI(endpoint)
	return parsed.Path
}

func endpointQuery(endpoint string) string {
	parsed, _ := url.ParseRequestURI(endpoint)
	return parsed.RawQuery
}

func claimString(value interface{}) string {
	text, _ := value.(string)
	return strings.TrimSpace(text)
}

func claimUnixTime(value interface{}) (time.Time, error) {
	var seconds int64
	var err error
	switch typed := value.(type) {
	case json.Number:
		seconds, err = typed.Int64()
	case float64:
		seconds = int64(typed)
	default:
		err = errors.New("invalid timestamp")
	}
	if err != nil || seconds <= 0 {
		return time.Time{}, errors.New("invalid timestamp")
	}
	return time.Unix(seconds, 0).UTC(), nil
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}

func writeReport(path string, body []byte) error {
	cleaned := filepath.Clean(path)
	if err := os.MkdirAll(filepath.Dir(cleaned), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(cleaned, append(body, '\n'), 0o600); err != nil {
		return err
	}
	return os.Chmod(cleaned, 0o600)
}

func envOr(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func durationEnv(key string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

func boolEnv(key string) bool {
	value, _ := strconv.ParseBool(strings.TrimSpace(os.Getenv(key)))
	return value
}
