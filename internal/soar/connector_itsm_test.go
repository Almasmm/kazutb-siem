package soar

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/kcsp/platform/internal/core"
)

func TestNormalizeNativeITSMConnectorContracts(t *testing.T) {
	secretRef := "env://KCSP_CONNECTOR_SECRET_ITSM_NATIVE"
	serviceNow, err := normalizeConnectorDraft(ConnectorDraft{
		Name: "University ServiceNow", Kind: core.SOARConnectorKindITSMREST,
		Endpoint: "https://university.service-now.com", AuthType: core.SOARConnectorAuthBasic,
		SecretRef: secretRef, AllowedActions: []string{
			"kcsp.ticket.create", "kcsp.ticket.update", "kcsp.ticket.comment", "kcsp.ticket.close",
		}, Settings: map[string]interface{}{"provider": "SERVICENOW"},
	})
	if err != nil || serviceNow.Settings["provider"] != itsmProviderServiceNow {
		t.Fatalf("normalize ServiceNow connector: connector=%+v err=%v", serviceNow, err)
	}
	jira, err := normalizeConnectorDraft(ConnectorDraft{
		Name: "University Jira", Kind: core.SOARConnectorKindITSMREST,
		Endpoint: "https://university.atlassian.net", AuthType: core.SOARConnectorAuthBearer,
		SecretRef: secretRef, AllowedActions: []string{"kcsp.ticket.create", "kcsp.ticket.close"},
		Settings: map[string]interface{}{
			"provider": "JIRA", "project_key": "soc", "issue_type": "Incident", "close_transition_id": "31",
		},
	})
	if err != nil || jira.Settings["project_key"] != "SOC" || jira.Settings["issue_type"] != "Incident" {
		t.Fatalf("normalize Jira connector: connector=%+v err=%v", jira, err)
	}
	invalid := []map[string]interface{}{
		{"provider": "JIRA"},
		{"provider": "JIRA", "project_key": "SOC", "close_transition_id": "close"},
		{"provider": "SERVICENOW", "project_key": "SOC"},
		{"provider": "UNSUPPORTED"},
	}
	for index, settings := range invalid {
		if _, err := normalizeConnectorDraft(ConnectorDraft{
			Name: "Invalid ITSM", Kind: core.SOARConnectorKindITSMREST,
			Endpoint: "https://itsm.example.edu", AuthType: core.SOARConnectorAuthBearer,
			SecretRef: secretRef, AllowedActions: []string{"kcsp.ticket.create"}, Settings: settings,
		}); err == nil {
			t.Fatalf("invalid native ITSM settings %d were accepted", index)
		}
	}
}

func TestManagedServiceNowConnectorExecutesTicketLifecycleWithVerification(t *testing.T) {
	const sysID = "0123456789abcdef0123456789abcdef"
	t.Setenv("KCSP_CONNECTOR_SECRET_SERVICENOW", "soc-user:soc-password")
	var writes atomic.Int32
	var reads atomic.Int32
	var closed atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte("soc-user:soc-password")) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet && r.URL.Path == "/api/now/table/incident/"+sysID {
			reads.Add(1)
			state := "2"
			if closed.Load() {
				state = "7"
			}
			_, _ = w.Write([]byte(`{"result":{"sys_id":"` + sysID + `","number":"INC0010042","state":"` + state + `"}}`))
			return
		}
		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "invalid payload", http.StatusBadRequest)
			return
		}
		writes.Add(1)
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/now/table/incident":
			if payload["short_description"] != "Investigate ransomware" || payload["correlation_id"] == "" {
				http.Error(w, "invalid create", http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"result":{"sys_id":"` + sysID + `","number":"INC0010042"}}`))
		case r.Method == http.MethodPatch && r.URL.Path == "/api/now/table/incident/"+sysID:
			if payload["state"] == "7" {
				closed.Store(true)
			}
			_, _ = w.Write([]byte(`{"result":{"sys_id":"` + sysID + `"}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	actions := []string{"kcsp.ticket.create", "kcsp.ticket.update", "kcsp.ticket.comment", "kcsp.ticket.close"}
	store := &typedConnectorRuntimeStore{connector: core.SOARConnector{
		ID: "servicenow-1", TenantID: "tenant-a", Kind: core.SOARConnectorKindITSMREST,
		State: core.SOARConnectorReady, HealthStatus: core.SOARConnectorHealthHealthy,
		Endpoint: server.URL, AuthType: core.SOARConnectorAuthBasic,
		SecretRef: "env://KCSP_CONNECTOR_SECRET_SERVICENOW", AllowedActions: actions,
		Settings: map[string]interface{}{"provider": itsmProviderServiceNow}, TimeoutSeconds: 5, RateLimitPerMinute: 20,
	}}
	executor := NewManagedConnectorExecutor(store, EnvironmentSecretResolver{}, server.Client())
	requests := []struct {
		action string
		risk   int
		params map[string]interface{}
	}{
		{action: "kcsp.ticket.create", risk: 1, params: map[string]interface{}{"title": "Investigate ransomware", "description": "Host isolated"}},
		{action: "kcsp.ticket.update", risk: 1, params: map[string]interface{}{"ticket_id": sysID, "title": "Ransomware contained"}},
		{action: "kcsp.ticket.comment", risk: 1, params: map[string]interface{}{"ticket_id": sysID, "comment": "Evidence attached"}},
		{action: "kcsp.ticket.close", risk: 2, params: map[string]interface{}{"ticket_id": sysID, "reason": "Containment verified"}},
	}
	for index, item := range requests {
		result, err := executor.Execute(context.Background(), ActionRequest{Attempt: core.SOARActionAttempt{
			TenantID: "tenant-a", ConnectorID: "servicenow-1", ActionType: item.action, RiskLevel: item.risk,
			Mode: "LIVE", IdempotencyKey: "exec-1|" + item.action, ExecutionID: "exec-1", Request: item.params,
		}})
		if err != nil || result.VerificationStatus != "VERIFIED" || result.Output["ticket_id"] != sysID {
			t.Fatalf("ServiceNow lifecycle action %d failed: result=%+v err=%v", index, result, err)
		}
	}
	if writes.Load() != 4 || reads.Load() != 4 || store.reservations != 4 || !closed.Load() {
		t.Fatalf("ServiceNow lifecycle was incomplete: writes=%d reads=%d reservations=%d closed=%v",
			writes.Load(), reads.Load(), store.reservations, closed.Load())
	}
}

func TestManagedJIRAConnectorUsesADFTransitionAndHealthContracts(t *testing.T) {
	t.Setenv("KCSP_CONNECTOR_SECRET_JIRA", "jira-api-token")
	var comments atomic.Int32
	var transitions atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer jira-api-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/rest/api/3/myself":
			_, _ = w.Write([]byte(`{"accountId":"kcsp-soc"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/rest/api/3/issue/SOC-42":
			_, _ = w.Write([]byte(`{"id":"10042","key":"SOC-42","fields":{"status":{"name":"Done"}}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/rest/api/3/issue/SOC-42/comment":
			var payload map[string]interface{}
			if json.NewDecoder(r.Body).Decode(&payload) != nil || !strings.Contains(stringMustJSON(payload["body"]), `"type":"doc"`) {
				http.Error(w, "comment is not ADF", http.StatusBadRequest)
				return
			}
			comments.Add(1)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"9001"}`))
		case r.Method == http.MethodPost && r.URL.Path == "/rest/api/3/issue/SOC-42/transitions":
			var payload map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&payload)
			transition, _ := payload["transition"].(map[string]interface{})
			if transition["id"] != "31" {
				http.Error(w, "wrong transition", http.StatusBadRequest)
				return
			}
			transitions.Add(1)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	connector := core.SOARConnector{
		ID: "jira-1", TenantID: "tenant-a", Kind: core.SOARConnectorKindITSMREST,
		State: core.SOARConnectorReady, HealthStatus: core.SOARConnectorHealthHealthy,
		Endpoint: server.URL, AuthType: core.SOARConnectorAuthBearer,
		SecretRef:      "env://KCSP_CONNECTOR_SECRET_JIRA",
		AllowedActions: []string{"kcsp.ticket.comment", "kcsp.ticket.close"},
		Settings: map[string]interface{}{
			"provider": itsmProviderJIRA, "project_key": "SOC", "issue_type": "Incident", "close_transition_id": "31",
		}, TimeoutSeconds: 5, RateLimitPerMinute: 20,
	}
	store := &typedConnectorRuntimeStore{connector: connector}
	executor := NewManagedConnectorExecutor(store, EnvironmentSecretResolver{}, server.Client())
	for _, item := range []struct {
		action string
		risk   int
		params map[string]interface{}
	}{
		{action: "kcsp.ticket.comment", risk: 1, params: map[string]interface{}{"ticket_key": "SOC-42", "comment": "IOC validated"}},
		{action: "kcsp.ticket.close", risk: 2, params: map[string]interface{}{"ticket_key": "SOC-42", "reason": "Response complete"}},
	} {
		result, err := executor.Execute(context.Background(), ActionRequest{Attempt: core.SOARActionAttempt{
			TenantID: "tenant-a", ConnectorID: "jira-1", ActionType: item.action, RiskLevel: item.risk,
			Mode: "LIVE", IdempotencyKey: "exec-2|" + item.action, ExecutionID: "exec-2", Request: item.params,
		}})
		if err != nil || result.VerificationStatus != "VERIFIED" || result.Output["ticket_key"] != "SOC-42" {
			t.Fatalf("Jira action failed: action=%s result=%+v err=%v", item.action, result, err)
		}
	}
	if comments.Load() != 1 || transitions.Load() != 1 || store.reservations != 2 {
		t.Fatalf("Jira action calls were incomplete: comments=%d transitions=%d reservations=%d",
			comments.Load(), transitions.Load(), store.reservations)
	}
	health, err := executor.TestConnector(context.Background(), connector)
	if err != nil || health.Status != core.SOARConnectorTestSucceeded || health.HTTPStatus != http.StatusOK {
		t.Fatalf("Jira native health failed: result=%+v err=%v", health, err)
	}
}

func stringMustJSON(value interface{}) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}
