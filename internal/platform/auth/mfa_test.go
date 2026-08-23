package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestOIDCAuthenticatorRequiresMFAAssurance(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	provider := newTestOIDCProvider(t, &privateKey.PublicKey)
	defer provider.Close()
	authenticator, err := NewOIDCAuthenticator(context.Background(), OIDCConfig{
		IssuerURL: provider.URL, ClientID: "kcsp-web", AllowInsecureIssuer: true, RequireMFA: true,
		MFAAMRValues: []string{"mfa", "webauthn"}, MFAACRValues: []string{"urn:kcsp:assurance:high"},
	})
	if err != nil {
		t.Fatal(err)
	}
	claims := mfaTestClaims(provider.URL)
	if _, err := authenticateMFAClaims(t, authenticator, privateKey, claims); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("token without MFA assurance was accepted: %v", err)
	}
	claims["amr"] = []string{"pwd", "WebAuthn"}
	if principal, err := authenticateMFAClaims(t, authenticator, privateKey, claims); err != nil || principal.ID != "analyst-mfa" {
		t.Fatalf("WebAuthn assurance rejected: principal=%+v err=%v", principal, err)
	}
	delete(claims, "amr")
	claims["acr"] = "urn:kcsp:assurance:high"
	if _, err := authenticateMFAClaims(t, authenticator, privateKey, claims); err != nil {
		t.Fatalf("allowed ACR assurance rejected: %v", err)
	}
}

func TestOIDCAuthenticatorEnforcesAuthenticationAge(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	provider := newTestOIDCProvider(t, &privateKey.PublicKey)
	defer provider.Close()
	now := time.Date(2026, 8, 23, 7, 15, 0, 0, time.UTC)
	authenticator, err := NewOIDCAuthenticator(context.Background(), OIDCConfig{
		IssuerURL: provider.URL, ClientID: "kcsp-web", AllowInsecureIssuer: true, RequireMFA: true,
		MFAAMRValues: []string{"mfa"}, MaximumAuthAge: 15 * time.Minute, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	claims := mfaTestClaims(provider.URL)
	claims["amr"] = []string{"pwd", "mfa"}
	claims["auth_time"] = now.Add(-time.Hour).Unix()
	if _, err := authenticateMFAClaims(t, authenticator, privateKey, claims); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("stale MFA session was accepted: %v", err)
	}
	claims["auth_time"] = now.Add(-5 * time.Minute).Unix()
	if _, err := authenticateMFAClaims(t, authenticator, privateKey, claims); err != nil {
		t.Fatalf("fresh MFA session rejected: %v", err)
	}
}

func mfaTestClaims(issuer string) map[string]interface{} {
	return map[string]interface{}{
		"iss": issuer, "aud": "kcsp-web", "sub": "analyst-mfa", "name": "MFA Analyst",
		"iat": time.Now().Add(-time.Minute).Unix(), "exp": time.Now().Add(5 * time.Minute).Unix(),
		"kcsp_tenants": []string{"tenant-a"}, "kcsp_roles": []string{"soc_l2"},
	}
}

func authenticateMFAClaims(t *testing.T, authenticator *OIDCAuthenticator, privateKey *rsa.PrivateKey, claims map[string]interface{}) (Principal, error) {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "https://kcsp.local/api/v1/session", nil)
	request.Header.Set("Authorization", "Bearer "+signTestJWT(t, privateKey, claims))
	return authenticator.Authenticate(request)
}
