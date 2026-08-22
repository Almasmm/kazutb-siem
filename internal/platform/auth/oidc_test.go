package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestOIDCAuthenticatorVerifiesTokenAndMapsTenantScopedRBAC(t *testing.T) {
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
		"iss": provider.URL, "aud": "kcsp-web", "sub": "analyst-42", "name": "Dana Analyst",
		"iat": time.Now().Add(-time.Minute).Unix(), "exp": time.Now().Add(5 * time.Minute).Unix(),
		"kcsp_tenants": []string{"tenant-a"},
		"realm_access": map[string]interface{}{"roles": []string{"kcsp-soc-l2"}},
	}
	request := httptest.NewRequest(http.MethodGet, "https://kcsp.local/api/v1/alerts", nil)
	request.Header.Set("Authorization", "Bearer "+signTestJWT(t, privateKey, claims))
	principal, err := authenticator.Authenticate(request)
	if err != nil {
		t.Fatal(err)
	}
	if principal.ID != "analyst-42" || principal.DisplayName != "Dana Analyst" || principal.Role != "SOC L2" {
		t.Fatalf("unexpected principal: %+v", principal)
	}
	if !principal.Can("soc.incidents.manage") || !principal.Can("siem.events.read") {
		t.Fatalf("SOC L2 permissions missing: %+v", principal.Permissions)
	}
	if !principal.CanAccessTenant("tenant-a") || principal.CanAccessTenant("tenant-b") {
		t.Fatalf("tenant isolation failed: %+v", principal.AllowedTenants)
	}
}

func TestOIDCAuthenticatorRejectsWrongAudienceAndMissingTenant(t *testing.T) {
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
	base := map[string]interface{}{
		"iss": provider.URL, "sub": "analyst-42", "iat": time.Now().Add(-time.Minute).Unix(),
		"exp": time.Now().Add(5 * time.Minute).Unix(), "realm_access": map[string]interface{}{"roles": []string{"soc_l1"}},
	}
	wrongAudience := cloneClaims(base)
	wrongAudience["aud"] = "another-client"
	wrongAudience["kcsp_tenants"] = []string{"tenant-a"}
	request := httptest.NewRequest(http.MethodGet, "https://kcsp.local", nil)
	request.Header.Set("Authorization", "Bearer "+signTestJWT(t, privateKey, wrongAudience))
	if _, err := authenticator.Authenticate(request); err == nil {
		t.Fatal("wrong audience token was accepted")
	}
	missingTenant := cloneClaims(base)
	missingTenant["aud"] = "kcsp-web"
	request = httptest.NewRequest(http.MethodGet, "https://kcsp.local", nil)
	request.Header.Set("Authorization", "Bearer "+signTestJWT(t, privateKey, missingTenant))
	if _, err := authenticator.Authenticate(request); err == nil {
		t.Fatal("tenant-less non-platform token was accepted")
	}
}

func TestPlatformSuperAdminUsesExplicitPlatformScope(t *testing.T) {
	permissions, names, platformScope := permissionsForRoles([]string{"platform_super_admin"})
	principal := Principal{Permissions: permissions, Role: names[0], PlatformScope: platformScope, AllowedTenants: map[string]bool{}}
	if !principal.Can("any.future.permission") || !principal.CanAccessTenant("tenant-any") || principal.Role != "Platform Super Admin" {
		t.Fatalf("unexpected platform principal: %+v", principal)
	}
}

func newTestOIDCProvider(t *testing.T, publicKey *rsa.PublicKey) *httptest.Server {
	t.Helper()
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"issuer": server.URL, "jwks_uri": server.URL + "/keys",
				"authorization_endpoint": server.URL + "/authorize", "token_endpoint": server.URL + "/token",
				"id_token_signing_alg_values_supported": []string{"RS256"},
			})
		case "/keys":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"keys": []map[string]string{{
				"kty": "RSA", "kid": "test-key", "use": "sig", "alg": "RS256",
				"n": base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes()),
			}}})
		default:
			http.NotFound(w, r)
		}
	}))
	return server
}

func signTestJWT(t *testing.T, privateKey *rsa.PrivateKey, claims map[string]interface{}) string {
	t.Helper()
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "test-key", "typ": "JWT"})
	payload, _ := json.Marshal(claims)
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func cloneClaims(source map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{}, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}
