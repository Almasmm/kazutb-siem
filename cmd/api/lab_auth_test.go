package main

import (
	"context"
	"net/http"
	"testing"
)

func TestConfigureLabAuthenticatorRequiresRuntimeSecret(t *testing.T) {
	t.Setenv("KCSP_LAB_ADMIN_TOKEN", "")
	if _, err := configureAuthenticator(context.Background(), "development", "demo", true); err == nil {
		t.Fatal("lab authenticator accepted a missing runtime secret")
	}

	secret := "kcsp_lab_test_runtime_secret_that_is_long_enough"
	t.Setenv("KCSP_LAB_ADMIN_TOKEN", secret)
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

func TestConfigureLabAuthenticatorIsForbiddenInProduction(t *testing.T) {
	t.Setenv("KCSP_LAB_ADMIN_TOKEN", "kcsp_lab_test_runtime_secret_that_is_long_enough")
	if _, err := configureAuthenticator(context.Background(), "production", "demo", true); err == nil {
		t.Fatal("production accepted development lab authentication")
	}
}
