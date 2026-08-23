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

func TestPrincipalRequiresCanonicalTenantEvenWithPlatformScope(t *testing.T) {
	t.Parallel()
	principal := Principal{
		AllowedTenants: map[string]bool{"tenant-a": true, "../tenant-b": true},
		PlatformScope:  true,
	}
	if !principal.CanAccessTenant("tenant-a") {
		t.Fatal("canonical tenant was denied")
	}
	for _, tenantID := range []string{"", "Tenant-a", "../tenant-b", "tenant-a/objects"} {
		if principal.CanAccessTenant(tenantID) {
			t.Fatalf("non-canonical tenant %q was accepted", tenantID)
		}
	}
}

func TestOIDCAuthenticatorRejectsMalformedTenantMembership(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	provider := newTestOIDCProvider(t, &privateKey.PublicKey)
	defer provider.Close()
	authenticator, err := NewOIDCAuthenticator(context.Background(), OIDCConfig{IssuerURL: provider.URL, ClientID: "kcsp-web"})
	if err != nil {
		t.Fatal(err)
	}
	claims := map[string]interface{}{
		"iss": provider.URL, "aud": "kcsp-web", "sub": "analyst-42",
		"iat": time.Now().Add(-time.Minute).Unix(), "exp": time.Now().Add(5 * time.Minute).Unix(),
		"kcsp_tenants": []string{"tenant-a", "../tenant-b"},
		"realm_access": map[string]interface{}{"roles": []string{"kcsp-soc-l2"}},
	}
	request := httptest.NewRequest(http.MethodGet, "https://kcsp.local/api/v1/alerts", nil)
	request.Header.Set("Authorization", "Bearer "+signTestJWT(t, privateKey, claims))
	if _, err := authenticator.Authenticate(request); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("malformed tenant claim error = %v, want ErrUnauthenticated", err)
	}
}
