package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestRunAcceptanceProvesTwoWayTenantIsolationWithoutLeakingTokens(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.August, 23, 8, 0, 0, 0, time.UTC)
	tokenA := testJWT(t, "analyst-a-sensitive", "tenant-a", now.Add(time.Hour))
	tokenB := testJWT(t, "analyst-b-sensitive", "tenant-b", now.Add(time.Hour))
	allowed := map[string]string{tokenA: "tenant-a", tokenB: "tenant-b"}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		tokenValue := strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer ")
		tenantHeaders := request.Header.Values("X-KCSP-Tenant-ID")
		if expected, found := allowed[tokenValue]; found && len(tenantHeaders) == 1 && tenantHeaders[0] == expected {
			response.Header().Set("Content-Type", "application/json")
			_, _ = response.Write([]byte(`{"items":[]}`))
			return
		}
		response.Header().Set("Content-Type", "application/problem+json")
		response.WriteHeader(http.StatusForbidden)
		_, _ = response.Write([]byte(`{"code":"tenant_denied"}`))
	}))
	defer server.Close()
	baseURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	report, err := runAcceptance(context.Background(), acceptanceConfig{
		BaseURL: baseURL, TenantA: "tenant-a", TenantB: "tenant-b", TokenA: tokenA, TokenB: tokenB,
		TenantClaim: "kcsp_tenants", Endpoints: []string{"/api/v1/overview", "/api/v1/events?limit=1"},
		Client: server.Client(), Now: func() time.Time { return now }, AllowLoopbackHTTP: true,
	})
	if err != nil || !report.Passed || !report.DistinctSubjects || len(report.Checks) != 10 {
		t.Fatalf("acceptance report=%+v err=%v", report, err)
	}
	body, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{tokenA, tokenB, "analyst-a-sensitive", "analyst-b-sensitive"} {
		if strings.Contains(string(body), secret) {
			t.Fatalf("secret identity material leaked into report: %q", secret)
		}
	}
}

func TestOIDCPreflightRejectsSharedOrCrossTenantMembership(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.August, 23, 8, 0, 0, 0, time.UTC)
	claims := map[string]interface{}{
		"iss": "https://identity.example.edu", "sub": "shared-user", "exp": now.Add(time.Hour).Unix(),
		"kcsp_tenants": []string{"tenant-a", "tenant-b"},
	}
	tokenValue := encodeTestJWT(t, claims)
	if _, err := parseOIDCIdentity(tokenValue, "kcsp_tenants", "tenant-a", "tenant-b", now); err == nil {
		t.Fatal("cross-tenant membership was accepted as an isolated identity")
	}
}

func TestConfigRejectsRemotePlaintextAPI(t *testing.T) {
	t.Parallel()
	baseURL, err := url.Parse("http://soc.example.edu")
	if err != nil {
		t.Fatal(err)
	}
	config := acceptanceConfig{
		BaseURL: baseURL, TenantA: "tenant-a", TenantB: "tenant-b", TokenA: "a.b.c", TokenB: "d.e.f",
		TenantClaim: "kcsp_tenants", Endpoints: []string{"/api/v1/overview"}, Client: http.DefaultClient, Now: time.Now,
	}
	if err := validateConfig(config); err == nil {
		t.Fatal("remote plaintext API was accepted")
	}
}

func testJWT(t *testing.T, subject, tenantID string, expires time.Time) string {
	t.Helper()
	return encodeTestJWT(t, map[string]interface{}{
		"iss": "https://identity.example.edu", "sub": subject, "exp": expires.Unix(), "kcsp_tenants": []string{tenantID},
	})
}

func encodeTestJWT(t *testing.T, claims map[string]interface{}) string {
	t.Helper()
	header, err := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload) + ".signature"
}
