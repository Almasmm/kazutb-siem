package ephemeral

import (
	"testing"
)

func TestValkeyOptionsEnforceProductionTransportAndAuthentication(t *testing.T) {
	if _, _, err := valkeyOptions(ValkeyConfig{URL: "redis://valkey:6379/0", RequireTLS: true}); err == nil {
		t.Fatal("plaintext Valkey URL was accepted when TLS is required")
	}
	if _, _, err := valkeyOptions(ValkeyConfig{URL: "rediss://valkey:6379/0", RequireAuthentication: true}); err == nil {
		t.Fatal("anonymous Valkey URL was accepted when authentication is required")
	}
	options, namespace, err := valkeyOptions(ValkeyConfig{
		URL: "rediss://kcsp@valkey:6379/0", Password: "secret", Namespace: "kcsp:tenant-state",
		RequireTLS: true, RequireAuthentication: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if options.Username != "kcsp" || options.Password != "secret" || options.TLSConfig == nil || namespace != "kcsp:tenant-state" {
		t.Fatalf("unexpected secure Valkey options: username=%q tls=%v namespace=%q", options.Username, options.TLSConfig != nil, namespace)
	}
}

func TestValkeyOptionsRejectUnsafeNamespace(t *testing.T) {
	if _, _, err := valkeyOptions(ValkeyConfig{URL: "redis://valkey:6379/0", Namespace: "kcsp tenant *"}); err == nil {
		t.Fatal("unsafe Valkey namespace was accepted")
	}
}
