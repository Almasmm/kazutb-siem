package soar

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/kcsp/platform/internal/core"
)

type edrRoundTripperFunc func(*http.Request) (*http.Response, error)

func (fn edrRoundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func edrResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}
}

func TestNormalizeNativeEDRXDRProviders(t *testing.T) {
	valid := []ConnectorDraft{
		{Name: "Defender", Kind: core.SOARConnectorKindEDRXDRREST, Endpoint: "https://api.security.microsoft.com",
			AuthType: core.SOARConnectorAuthOAuth2ClientCredentials, SecretRef: "env://KCSP_CONNECTOR_SECRET_MDE",
			AllowedActions: []string{"endpoint.isolate", "endpoint.release"}, Settings: map[string]interface{}{"provider": edrXDRProviderMicrosoftDefender}},
		{Name: "Falcon", Kind: core.SOARConnectorKindEDRXDRREST, Endpoint: "https://api.eu-1.crowdstrike.com",
			AuthType: core.SOARConnectorAuthOAuth2ClientCredentials, SecretRef: "env://KCSP_CONNECTOR_SECRET_FALCON",
			AllowedActions: []string{"endpoint.isolate"}, Settings: map[string]interface{}{"provider": edrXDRProviderCrowdStrikeFalcon}},
	}
	for _, draft := range valid {
		if _, err := normalizeConnectorDraft(draft); err != nil {
			t.Fatalf("native provider rejected: %v", err)
		}
	}
	invalid := valid[0]
	invalid.AuthType = core.SOARConnectorAuthBearer
	if _, err := normalizeConnectorDraft(invalid); err == nil {
		t.Fatal("native provider accepted static bearer auth")
	}
	invalid = valid[0]
	invalid.Endpoint = "https://defender-proxy.example.edu"
	if _, err := normalizeConnectorDraft(invalid); err == nil {
		t.Fatal("native provider accepted a non-provider endpoint")
	}
}

func TestMicrosoftDefenderNativeActionAndHealth(t *testing.T) {
	const machineID = "0123456789abcdef0123456789abcdef01234567"
	const actionID = "11111111-2222-3333-4444-555555555555"
	t.Setenv("KCSP_CONNECTOR_SECRET_MDE", `{"tenant_id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","client_id":"11111111-2222-3333-4444-555555555555","client_secret":"mde-secret"}`)
	tokenCalls := 0
	client := &http.Client{Transport: edrRoundTripperFunc(func(request *http.Request) (*http.Response, error) {
		switch {
		case request.URL.Host == "login.microsoftonline.com":
			tokenCalls++
			payload, _ := io.ReadAll(request.Body)
			values, _ := url.ParseQuery(string(payload))
			if values.Get("scope") != microsoftDefenderScope || values.Get("client_secret") != "mde-secret" {
				t.Fatalf("invalid MDE token request: %s", payload)
			}
			return edrResponse(http.StatusOK, `{"access_token":"mde-token","token_type":"Bearer","expires_in":3600}`), nil
		case request.Method == http.MethodPost && request.URL.Path == "/api/machines/"+machineID+"/isolate":
			if request.Header.Get("Authorization") != "Bearer mde-token" || request.Header.Get("X-KCSP-Idempotency-Key") != "exec-1|isolate" {
				t.Fatal("MDE action authentication or idempotency header missing")
			}
			var payload map[string]interface{}
			_ = json.NewDecoder(request.Body).Decode(&payload)
			if payload["IsolationType"] != "Full" {
				t.Fatalf("unexpected MDE payload: %+v", payload)
			}
			return edrResponse(http.StatusCreated, `{"id":"`+actionID+`","status":"Pending","machineId":"`+machineID+`","type":"Isolate"}`), nil
		case request.Method == http.MethodGet && request.URL.Path == "/api/machineactions/"+actionID:
			return edrResponse(http.StatusOK, `{"id":"`+actionID+`","status":"Succeeded","machineId":"`+machineID+`","type":"Isolate"}`), nil
		case request.Method == http.MethodGet && request.URL.Path == "/api/machines" && request.URL.Query().Get("$top") == "1":
			return edrResponse(http.StatusOK, `{"value":[]}`), nil
		default:
			t.Fatalf("unexpected MDE request: %s %s", request.Method, request.URL.String())
			return nil, nil
		}
	})}
	connector := core.SOARConnector{ID: "mde-1", TenantID: "tenant-a", Kind: core.SOARConnectorKindEDRXDRREST,
		State: core.SOARConnectorReady, HealthStatus: core.SOARConnectorHealthHealthy,
		Endpoint: "https://api.security.microsoft.com", AuthType: core.SOARConnectorAuthOAuth2ClientCredentials,
		SecretRef: "env://KCSP_CONNECTOR_SECRET_MDE", AllowedActions: []string{"endpoint.isolate"},
		Settings: map[string]interface{}{"provider": edrXDRProviderMicrosoftDefender}, TimeoutSeconds: 5, RateLimitPerMinute: 10}
	store := &typedConnectorRuntimeStore{connector: connector}
	executor := NewManagedConnectorExecutor(store, EnvironmentSecretResolver{}, client)
	result, err := executor.Execute(context.Background(), ActionRequest{Attempt: core.SOARActionAttempt{
		TenantID: "tenant-a", ConnectorID: connector.ID, ActionType: "endpoint.isolate", RiskLevel: 3, Mode: "LIVE",
		IdempotencyKey: "exec-1|isolate", ExecutionID: "exec-1", Request: map[string]interface{}{"endpoint_id": machineID, "reason": "confirmed compromise"},
	}})
	if err != nil || result.VerificationStatus != "VERIFIED" || result.Output["action_id"] != actionID || store.reservations != 1 {
		t.Fatalf("MDE action failed: result=%+v reservations=%d err=%v", result, store.reservations, err)
	}
	health, err := executor.TestConnector(context.Background(), connector)
	if err != nil || health.Status != core.SOARConnectorTestSucceeded || tokenCalls != 1 {
		t.Fatalf("MDE health or token cache failed: health=%+v token_calls=%d err=%v", health, tokenCalls, err)
	}
}

func TestCrowdStrikeNativeActionAndHealth(t *testing.T) {
	const agentID = "0123456789abcdef0123456789abcdef"
	t.Setenv("KCSP_CONNECTOR_SECRET_FALCON", `{"client_id":"falcon-client-123","client_secret":"falcon-secret"}`)
	tokenCalls := 0
	client := &http.Client{Transport: edrRoundTripperFunc(func(request *http.Request) (*http.Response, error) {
		switch {
		case request.URL.Path == "/oauth2/token":
			tokenCalls++
			return edrResponse(http.StatusOK, `{"access_token":"falcon-token","token_type":"bearer","expires_in":1800}`), nil
		case request.Method == http.MethodPost && request.URL.Path == "/devices/entities/devices-actions/v2":
			if request.URL.Query().Get("action_name") != "contain" || request.Header.Get("Authorization") != "Bearer falcon-token" {
				t.Fatal("invalid Falcon action request")
			}
			return edrResponse(http.StatusOK, `{"meta":{"trace_id":"falcon-trace-42"},"resources":[],"errors":[]}`), nil
		case request.Method == http.MethodPost && request.URL.Path == "/devices/entities/devices/v2":
			return edrResponse(http.StatusOK, `{"resources":[{"device_id":"`+agentID+`","status":"contained"}],"errors":[]}`), nil
		case request.Method == http.MethodGet && request.URL.Path == "/devices/queries/devices/v1":
			return edrResponse(http.StatusOK, `{"resources":[],"errors":[]}`), nil
		default:
			t.Fatalf("unexpected Falcon request: %s %s", request.Method, request.URL.String())
			return nil, nil
		}
	})}
	connector := core.SOARConnector{ID: "falcon-1", TenantID: "tenant-a", Kind: core.SOARConnectorKindEDRXDRREST,
		State: core.SOARConnectorReady, HealthStatus: core.SOARConnectorHealthHealthy,
		Endpoint: "https://api.crowdstrike.com", AuthType: core.SOARConnectorAuthOAuth2ClientCredentials,
		SecretRef: "env://KCSP_CONNECTOR_SECRET_FALCON", AllowedActions: []string{"endpoint.isolate"},
		Settings: map[string]interface{}{"provider": edrXDRProviderCrowdStrikeFalcon}, TimeoutSeconds: 5, RateLimitPerMinute: 10}
	store := &typedConnectorRuntimeStore{connector: connector}
	executor := NewManagedConnectorExecutor(store, EnvironmentSecretResolver{}, client)
	result, err := executor.Execute(context.Background(), ActionRequest{Attempt: core.SOARActionAttempt{
		TenantID: "tenant-a", ConnectorID: connector.ID, ActionType: "endpoint.isolate", RiskLevel: 3, Mode: "LIVE",
		IdempotencyKey: "exec-2|contain", ExecutionID: "exec-2", Request: map[string]interface{}{"endpoint_id": agentID},
	}})
	if err != nil || result.VerificationStatus != "VERIFIED" || result.Output["action_id"] != "falcon-trace-42" {
		t.Fatalf("Falcon action failed: result=%+v err=%v", result, err)
	}
	health, err := executor.TestConnector(context.Background(), connector)
	if err != nil || health.Status != core.SOARConnectorTestSucceeded || tokenCalls != 1 {
		t.Fatalf("Falcon health or token cache failed: health=%+v token_calls=%d err=%v", health, tokenCalls, err)
	}
}
