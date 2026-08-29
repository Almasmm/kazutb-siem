package main

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestConfigureLabAuthenticatorRequiresRuntimeSecret(t *testing.T) {
	t.Setenv("KCSP_LAB_ADMIN_TOKEN", "ignored-environment-token-must-not-be-used")
	t.Setenv("KCSP_LAB_ADMIN_CREDENTIAL_FILE", "")
	if _, err := configureAuthenticator(context.Background(), "development", "demo", true); err == nil {
		t.Fatal("lab authenticator accepted a missing runtime secret")
	}

	secret := "kcsp_lab_test_runtime_secret_that_is_long_enough"
	credentialPath := filepath.Join(t.TempDir(), "lab-api-credential.json")
	if err := os.WriteFile(credentialPath, []byte(`{"tenant_id":"kcsp-lab","principal":"svc-kcsp-lab-admin","access_token":"`+secret+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KCSP_LAB_ADMIN_CREDENTIAL_FILE", credentialPath)
	authenticator, err := configureAuthenticator(context.Background(), "development", "demo", true)
	if err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequest(http.MethodGet, "http://kcsp.local", nil)
	request.Header.Set("Authorization", "Bearer "+secret)
	principal, err := authenticator.Authenticate(request)
	if err != nil {
		t.Fatal(err)
	}
	if !principal.CanAccessTenant("kcsp-lab") || principal.CanAccessTenant("university-kulazhanov") || principal.PlatformScope {
		t.Fatalf("lab principal escaped tenant scope: %+v", principal)
	}
}

func TestConfigureLabAuthenticatorRejectsMismatchedCredentialFile(t *testing.T) {
	credentialPath := filepath.Join(t.TempDir(), "lab-api-credential.json")
	if err := os.WriteFile(credentialPath, []byte(`{"tenant_id":"university-kulazhanov","principal":"svc-kcsp-lab-admin","access_token":"kcsp_lab_test_runtime_secret_that_is_long_enough"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KCSP_LAB_ADMIN_CREDENTIAL_FILE", credentialPath)
	if _, err := configureAuthenticator(context.Background(), "development", "demo", true); err == nil {
		t.Fatal("lab authenticator accepted a credential file for another tenant")
	}
}

func TestConfigureLabAuthenticatorIsForbiddenInProduction(t *testing.T) {
	t.Setenv("KCSP_LAB_ADMIN_CREDENTIAL_FILE", filepath.Join(t.TempDir(), "missing.json"))
	if _, err := configureAuthenticator(context.Background(), "production", "demo", true); err == nil {
		t.Fatal("production accepted development lab authentication")
	}
}
