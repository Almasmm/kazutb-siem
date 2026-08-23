package soar

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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
		Kind: core.SOARConnectorKindWebhook, State: core.SOARConnectorCredentialsNeeded, Endpoint: "https://hooks.example.edu/kcsp",
		AuthType: core.SOARConnectorAuthHMAC, TimeoutSeconds: 1,
		Settings: map[string]interface{}{"health_method": "HEAD", "expected_status": 200},
	})
	if err != nil || result.Status != core.SOARConnectorTestCredentials ||
		result.ErrorClass != "CREDENTIALS_REQUIRED" {
		t.Fatalf("missing credential was not classified safely: %+v err=%v", result, err)
	}
}

func TestNormalizeTypedConnectorProfiles(t *testing.T) {
	secretRef := "env://KCSP_CONNECTOR_SECRET_TYPED"
	tests := []struct {
		kind     string
		action   string
		settings map[string]interface{}
	}{
		{kind: core.SOARConnectorKindFirewallREST, action: "firewall.block_ip"},
		{kind: core.SOARConnectorKindITSMREST, action: "kcsp.ticket.create"},
		{kind: core.SOARConnectorKindKCSPAPI, action: "threat_intel.indicator.submit"},
		{kind: core.SOARConnectorKindThreatIntelREST, action: "threat_intel.indicator.submit"},
		{kind: core.SOARConnectorKindNotification, action: "kcsp.notification.send", settings: map[string]interface{}{"provider": "SLACK", "channel": "#soc"}},
		{kind: core.SOARConnectorKindEDRXDRREST, action: "endpoint.isolate"},
	}
	for _, test := range tests {
		t.Run(test.kind, func(t *testing.T) {
			connector, err := normalizeConnectorDraft(ConnectorDraft{
				Name: test.kind, Kind: test.kind, Endpoint: "https://connector.example.edu/actions",
				AuthType: core.SOARConnectorAuthBearer, SecretRef: secretRef,
				AllowedActions: []string{test.action}, Settings: test.settings,
			})
			if err != nil || connector.Kind != test.kind || connector.State != core.SOARConnectorCredentialsNeeded {
				t.Fatalf("typed connector was not normalized: connector=%+v err=%v", connector, err)
			}
		})
	}

	if _, err := normalizeConnectorDraft(ConnectorDraft{
		Name: "Anonymous firewall", Kind: core.SOARConnectorKindFirewallREST,
		Endpoint: "https://firewall.example.edu/actions", AuthType: core.SOARConnectorAuthNone,
		AllowedActions: []string{"firewall.block_ip"},
	}); err == nil {
		t.Fatal("sensitive connector accepted anonymous authentication")
	}
	if _, err := normalizeConnectorDraft(ConnectorDraft{
		Name: "Cross-kind action", Kind: core.SOARConnectorKindITSMREST,
		Endpoint: "https://itsm.example.edu/actions", AuthType: core.SOARConnectorAuthBearer,
		SecretRef: secretRef, AllowedActions: []string{"firewall.block_ip"},
	}); err == nil {
		t.Fatal("connector accepted an action from another profile")
	}
}

func TestBuildTypedConnectorPayloadContracts(t *testing.T) {
	tests := []struct {
		kind       string
		action     string
		parameters map[string]interface{}
		wantSchema string
		operation  string
	}{
		{kind: core.SOARConnectorKindWebhook, action: "kcsp.ticket.create", parameters: map[string]interface{}{"title": "Investigate"}, wantSchema: "1.0"},
		{kind: core.SOARConnectorKindITSMREST, action: "kcsp.ticket.create", parameters: map[string]interface{}{"title": "Investigate"}, wantSchema: "kcsp.itsm.v1", operation: "create_ticket"},
		{kind: core.SOARConnectorKindNotification, action: "kcsp.notification.send", parameters: map[string]interface{}{"text": "Incident opened"}, wantSchema: "kcsp.notification.v1", operation: "send_message"},
		{kind: core.SOARConnectorKindFirewallREST, action: "firewall.block_ip", parameters: map[string]interface{}{"ip": "203.0.113.7"}, wantSchema: "kcsp.firewall.v1", operation: "block_ip"},
		{kind: core.SOARConnectorKindEDRXDRREST, action: "endpoint.isolate", parameters: map[string]interface{}{"endpoint_id": "host-42"}, wantSchema: "kcsp.edr-xdr.v1", operation: "isolate_endpoint"},
		{kind: core.SOARConnectorKindThreatIntelREST, action: "threat_intel.indicator.submit", parameters: map[string]interface{}{"indicator": "malware.example"}, wantSchema: "kcsp.threat-intel.v1", operation: "submit_indicator"},
		{kind: core.SOARConnectorKindKCSPAPI, action: "kcsp.ticket.create", parameters: map[string]interface{}{"title": "Investigate"}, wantSchema: "kcsp.internal.v1", operation: "kcsp.ticket.create"},
	}
	for _, test := range tests {
		t.Run(test.kind, func(t *testing.T) {
			payload, err := buildConnectorPayload(core.SOARConnector{Kind: test.kind, Settings: map[string]interface{}{}}, ActionRequest{
				Attempt: core.SOARActionAttempt{
					ActionType: test.action, IdempotencyKey: "idem-1", ExecutionID: "exec-1", Request: test.parameters,
				},
			})
			if err != nil {
				t.Fatalf("build payload: %v", err)
			}
			var body map[string]interface{}
			if err := json.Unmarshal(payload, &body); err != nil {
				t.Fatalf("decode payload: %v", err)
			}
			if body["schema_version"] != test.wantSchema {
				t.Fatalf("schema=%v, want %s", body["schema_version"], test.wantSchema)
			}
			if test.operation != "" && body["operation"] != test.operation {
				t.Fatalf("operation=%v, want %s", body["operation"], test.operation)
			}
		})
	}
}

type typedConnectorRuntimeStore struct {
	connector    core.SOARConnector
	reservations int
}

func (s *typedConnectorRuntimeStore) GetSOARConnector(context.Context, string, string) (core.SOARConnector, error) {
	return s.connector, nil
}

func (s *typedConnectorRuntimeStore) ReserveSOARConnectorCall(context.Context, string, string, int, time.Time) error {
	s.reservations++
	return nil
}

func TestManagedConnectorExecutesTypedFirewallContractAndEnforcesRisk(t *testing.T) {
	t.Setenv("KCSP_CONNECTOR_SECRET_FIREWALL", "firewall-api-token")
	var received map[string]interface{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Firewall-Key") != "firewall-api-token" ||
			r.Header.Get("X-KCSP-Connector-Kind") != core.SOARConnectorKindFirewallREST ||
			r.Header.Get("X-KCSP-Action") != "firewall.block_ip" {
			http.Error(w, "authentication or contract headers missing", http.StatusUnauthorized)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			http.Error(w, "invalid payload", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"action_id":"fw-action-42","verified":true}`))
	}))
	defer server.Close()

	store := &typedConnectorRuntimeStore{connector: core.SOARConnector{
		ID: "firewall-1", TenantID: "tenant-a", Kind: core.SOARConnectorKindFirewallREST,
		State: core.SOARConnectorReady, HealthStatus: core.SOARConnectorHealthHealthy,
		Endpoint: server.URL, AuthType: core.SOARConnectorAuthAPIKey,
		SecretRef: "env://KCSP_CONNECTOR_SECRET_FIREWALL", AllowedActions: []string{"firewall.block_ip"},
		Settings: map[string]interface{}{"api_key_header": "X-Firewall-Key"}, TimeoutSeconds: 5,
		RateLimitPerMinute: 10,
	}}
	executor := NewManagedConnectorExecutor(store, EnvironmentSecretResolver{}, server.Client())
	request := ActionRequest{Attempt: core.SOARActionAttempt{
		TenantID: "tenant-a", ConnectorID: "firewall-1", ActionType: "firewall.block_ip",
		RiskLevel: 5, Mode: "LIVE", IdempotencyKey: "exec-1|block", ExecutionID: "exec-1",
		Request: map[string]interface{}{"ip": "203.0.113.7", "reason": "confirmed IOC"},
	}}
	result, err := executor.Execute(context.Background(), request)
	if err != nil || result.VerificationStatus != "VERIFIED" || result.Output["action_id"] != "fw-action-42" {
		t.Fatalf("typed firewall execution failed: result=%+v err=%v", result, err)
	}
	if store.reservations != 1 || received["schema_version"] != "kcsp.firewall.v1" || received["operation"] != "block_ip" {
		t.Fatalf("typed firewall contract was not delivered: reservations=%d payload=%+v", store.reservations, received)
	}

	request.Attempt.RiskLevel = 1
	if _, err := executor.Execute(context.Background(), request); err == nil {
		t.Fatal("connector accepted a spoofed server-side risk level")
	}
	if store.reservations != 1 {
		t.Fatal("risk-spoofed action consumed connector quota")
	}
}
