package soar

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kcsp/platform/internal/core"
)

func TestNormalizeNativeNotificationConnectorContracts(t *testing.T) {
	secretRef := "env://KCSP_CONNECTOR_SECRET_NOTIFICATION_NATIVE"
	for _, test := range []struct {
		name     string
		settings map[string]interface{}
	}{
		{name: "Slack", settings: map[string]interface{}{"provider": notificationProviderSlackWebAPI, "channel": "C0123456789"}},
		{name: "Teams", settings: map[string]interface{}{"provider": notificationProviderTeamsGraph, "team_id": "fbe2bf47-16c8-47cf-b4a5-4b9b187c508b", "channel_id": "19:abc@thread.tacv2"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			connector, err := normalizeConnectorDraft(ConnectorDraft{Name: test.name, Kind: core.SOARConnectorKindNotification,
				Endpoint: "https://notification.example.edu", AuthType: core.SOARConnectorAuthBearer,
				SecretRef: secretRef, AllowedActions: []string{"kcsp.notification.send"}, Settings: test.settings})
			if err != nil || connector.Settings["provider"] != test.settings["provider"] {
				t.Fatalf("native notification connector rejected: connector=%+v err=%v", connector, err)
			}
		})
	}
	if _, err := normalizeConnectorDraft(ConnectorDraft{Name: "Unsafe native Slack", Kind: core.SOARConnectorKindNotification,
		Endpoint: "https://slack.com", AuthType: core.SOARConnectorAuthBasic, SecretRef: secretRef,
		AllowedActions: []string{"kcsp.notification.send"}, Settings: map[string]interface{}{"provider": notificationProviderSlackWebAPI, "channel": "#soc"}}); err == nil {
		t.Fatal("native Slack accepted non-Bearer authentication and a channel name")
	}
}

func TestManagedSlackNotificationPostsAndVerifiesMessage(t *testing.T) {
	t.Setenv("KCSP_CONNECTOR_SECRET_SLACK_NATIVE", "xoxb-test-token")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer xoxb-test-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/chat.postMessage":
			var payload map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&payload)
			if payload["channel"] != "C0123456789" || payload["text"] != "Incident INC-42 opened" || payload["client_msg_id"] == "" {
				http.Error(w, "contract", http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte(`{"ok":true,"channel":"C0123456789","ts":"1700000000.000100"}`))
		case "/api/conversations.history":
			if r.URL.Query().Get("channel") != "C0123456789" || r.URL.Query().Get("latest") != "1700000000.000100" {
				http.Error(w, "verify contract", http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte(`{"ok":true,"messages":[{"ts":"1700000000.000100"}]}`))
		case "/api/auth.test":
			_, _ = w.Write([]byte(`{"ok":true,"team_id":"T1"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	connector := core.SOARConnector{ID: "slack-1", TenantID: "tenant-a", Kind: core.SOARConnectorKindNotification,
		State: core.SOARConnectorReady, HealthStatus: core.SOARConnectorHealthHealthy, Endpoint: server.URL,
		AuthType: core.SOARConnectorAuthBearer, SecretRef: "env://KCSP_CONNECTOR_SECRET_SLACK_NATIVE",
		AllowedActions: []string{"kcsp.notification.send"}, Settings: map[string]interface{}{"provider": notificationProviderSlackWebAPI, "channel": "C0123456789"},
		TimeoutSeconds: 5, RateLimitPerMinute: 10}
	store := &typedConnectorRuntimeStore{connector: connector}
	executor := NewManagedConnectorExecutor(store, EnvironmentSecretResolver{}, server.Client())
	result, err := executor.Execute(context.Background(), ActionRequest{Attempt: core.SOARActionAttempt{
		TenantID: "tenant-a", ConnectorID: "slack-1", ActionType: "kcsp.notification.send", RiskLevel: 2,
		Mode: "LIVE", IdempotencyKey: "exec-1|notify", ExecutionID: "exec-1",
		Request: map[string]interface{}{"text": "Incident INC-42 opened"},
	}})
	if err != nil || result.VerificationStatus != "VERIFIED" || result.Output["message_id"] != "1700000000.000100" || store.reservations != 1 {
		t.Fatalf("Slack notification failed: result=%+v reservations=%d err=%v", result, store.reservations, err)
	}
	health, err := executor.TestConnector(context.Background(), connector)
	if err != nil || health.Status != core.SOARConnectorTestSucceeded {
		t.Fatalf("Slack health failed: result=%+v err=%v", health, err)
	}
}

func TestManagedTeamsGraphNotificationPostsAndVerifiesMessage(t *testing.T) {
	const teamID = "fbe2bf47-16c8-47cf-b4a5-4b9b187c508b"
	const channelID = "19:abc@thread.tacv2"
	t.Setenv("KCSP_CONNECTOR_SECRET_TEAMS_NATIVE", "teams-access-token")
	basePath := "/v1.0/teams/" + teamID + "/channels/" + channelID
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer teams-access-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == basePath+"/messages":
			var payload map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&payload)
			body, _ := payload["body"].(map[string]interface{})
			if body["contentType"] != "text" || body["content"] != "Containment completed" {
				http.Error(w, "contract", http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"1616990032035"}`))
		case r.Method == http.MethodGet && r.URL.Path == basePath+"/messages/1616990032035":
			_, _ = w.Write([]byte(`{"id":"1616990032035","body":{"contentType":"text","content":"Containment completed"}}`))
		case r.Method == http.MethodGet && r.URL.Path == basePath:
			_, _ = w.Write([]byte(`{"id":"19:abc@thread.tacv2"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	connector := core.SOARConnector{ID: "teams-1", TenantID: "tenant-a", Kind: core.SOARConnectorKindNotification,
		State: core.SOARConnectorReady, HealthStatus: core.SOARConnectorHealthHealthy, Endpoint: server.URL,
		AuthType: core.SOARConnectorAuthBearer, SecretRef: "env://KCSP_CONNECTOR_SECRET_TEAMS_NATIVE",
		AllowedActions: []string{"kcsp.notification.send"}, Settings: map[string]interface{}{
			"provider": notificationProviderTeamsGraph, "team_id": teamID, "channel_id": channelID,
		}, TimeoutSeconds: 5, RateLimitPerMinute: 10}
	store := &typedConnectorRuntimeStore{connector: connector}
	executor := NewManagedConnectorExecutor(store, EnvironmentSecretResolver{}, server.Client())
	result, err := executor.Execute(context.Background(), ActionRequest{Attempt: core.SOARActionAttempt{
		TenantID: "tenant-a", ConnectorID: "teams-1", ActionType: "kcsp.notification.send", RiskLevel: 2,
		Mode: "LIVE", IdempotencyKey: "exec-2|notify", ExecutionID: "exec-2",
		Request: map[string]interface{}{"text": "Containment completed"},
	}})
	if err != nil || result.VerificationStatus != "VERIFIED" || result.Output["message_id"] != "1616990032035" {
		t.Fatalf("Teams notification failed: result=%+v err=%v", result, err)
	}
	health, err := executor.TestConnector(context.Background(), connector)
	if err != nil || health.Status != core.SOARConnectorTestSucceeded {
		t.Fatalf("Teams health failed: result=%+v err=%v", health, err)
	}
}
