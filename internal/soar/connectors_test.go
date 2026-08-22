package soar

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kcsp/platform/internal/core"
)

func TestNormalizeConnectorRejectsSecretMaterialAndUnsafeEndpoints(t *testing.T) {
	valid := ConnectorDraft{
		Name: "SOC notifications", Kind: "WEBHOOK", Endpoint: "https://hooks.example.edu/kcsp",
		AuthType: "BEARER", SecretRef: "env://KCSP_CONNECTOR_SECRET_SOC",
		AllowedActions: []string{"kcsp.notification.send"},
	}
	if _, err := normalizeConnectorDraft(valid); err != nil {
		t.Fatalf("valid connector rejected: %v", err)
	}
	invalid := []ConnectorDraft{
		func() ConnectorDraft { item := valid; item.Endpoint = "http://127.0.0.1/hook"; return item }(),
		func() ConnectorDraft { item := valid; item.SecretRef = "plaintext-secret"; return item }(),
		func() ConnectorDraft {
			item := valid
			item.Settings = map[string]interface{}{"authorization": "Bearer secret"}
			return item
		}(),
		func() ConnectorDraft {
			item := valid
			item.AllowedActions = []string{"firewall.block_ip"}
			return item
		}(),
	}
	for index, draft := range invalid {
		if _, err := normalizeConnectorDraft(draft); err == nil {
			t.Fatalf("invalid connector %d was accepted", index)
		}
	}
}

func TestManagedConnectorTesterUsesBoundSecretWithoutPersistingIt(t *testing.T) {
	t.Setenv("KCSP_CONNECTOR_SECRET_TEST", "test-token")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead || r.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	executor := NewManagedConnectorExecutor(nil, EnvironmentSecretResolver{}, server.Client())
	result, err := executor.TestConnector(context.Background(), core.SOARConnector{
		ID: "connector-1", Kind: core.SOARConnectorKindWebhook, State: core.SOARConnectorCredentialsNeeded,
		Endpoint: server.URL, AuthType: core.SOARConnectorAuthBearer,
		SecretRef: "env://KCSP_CONNECTOR_SECRET_TEST", TimeoutSeconds: 5,
		Settings: map[string]interface{}{"health_method": "HEAD", "expected_status": 204},
	})
	if err != nil || result.Status != core.SOARConnectorTestSucceeded || result.HTTPStatus != http.StatusNoContent {
		t.Fatalf("unexpected connector test: %+v err=%v", result, err)
	}
}

func TestManagedConnectorTesterReportsCredentialsRequired(t *testing.T) {
	executor := NewManagedConnectorExecutor(nil, EnvironmentSecretResolver{}, nil)
	result, err := executor.TestConnector(context.Background(), core.SOARConnector{
		State: core.SOARConnectorCredentialsNeeded, Endpoint: "https://hooks.example.edu/kcsp",
		AuthType: core.SOARConnectorAuthHMAC, TimeoutSeconds: 1,
		Settings: map[string]interface{}{"health_method": "HEAD", "expected_status": 200},
	})
	if err != nil || result.Status != core.SOARConnectorTestCredentials ||
		result.ErrorClass != "CREDENTIALS_REQUIRED" {
		t.Fatalf("missing credential was not classified safely: %+v err=%v", result, err)
	}
}
