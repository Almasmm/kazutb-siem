package agent

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestForwarderCachesOAuthClientCredentialsToken(t *testing.T) {
	t.Parallel()
	var tokenRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/token":
			tokenRequests.Add(1)
			clientID, clientSecret, ok := request.BasicAuth()
			if !ok || clientID != "collector-client" || clientSecret != "collector-secret" || request.FormValue("grant_type") != "client_credentials" {
				t.Fatalf("invalid client credentials request")
			}
			_ = json.NewEncoder(response).Encode(map[string]interface{}{"access_token": "rotating-service-token", "token_type": "Bearer", "expires_in": 300})
		case "/api/v1/ingest/events":
			if request.Header.Get("Authorization") != "Bearer rotating-service-token" {
				t.Fatalf("OAuth token was not applied: %s", request.Header.Get("Authorization"))
			}
			response.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(response).Encode(map[string]interface{}{"event_id": request.Header.Get("X-KCSP-Event-ID"), "status": "QUEUED"})
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	forwarder, err := NewForwarder(ForwarderConfig{
		ServerURL: server.URL, TenantID: "tenant-a", OAuthTokenURL: server.URL + "/token",
		OAuthClientID: "collector-client", OAuthClientSecret: "collector-secret", AllowInsecureHTTP: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer forwarder.Close()
	for _, eventID := range []string{"event-1", "event-2"} {
		if _, err := forwarder.Send(t.Context(), Event{Format: "syslog-v1", EventID: eventID, Payload: []byte("<13>1 test")}); err != nil {
			t.Fatal(err)
		}
	}
	if got := tokenRequests.Load(); got != 1 {
		t.Fatalf("OAuth token requests = %d, want 1", got)
	}
}

func TestForwarderRejectsAmbiguousAuthentication(t *testing.T) {
	t.Parallel()
	_, err := NewForwarder(ForwarderConfig{
		ServerURL: "http://kcsp.local", TenantID: "tenant-a", AccessToken: "static",
		OAuthTokenURL: "http://idp.local/token", OAuthClientID: "client", OAuthClientSecret: "secret", AllowInsecureHTTP: true,
	})
	if err == nil {
		t.Fatal("ambiguous static and OAuth authentication was accepted")
	}
}
