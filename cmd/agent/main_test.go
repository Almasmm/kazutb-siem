package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	agentstate "github.com/kcsp/platform/internal/agent"
	"github.com/kcsp/platform/internal/core"
)

func TestRunEnrollOnlyPersistsAndReusesCredential(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/agent-enrollment" {
			http.NotFound(w, r)
			return
		}
		var request core.AgentEnrollmentRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if request.EnrollmentToken != "kcsp_enroll_test.secret" || request.AgentID != "agent-enroll-only" {
			http.Error(w, "unexpected enrollment request", http.StatusBadRequest)
			return
		}
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(core.AgentEnrollmentResponse{
			Collector: core.Collector{ID: request.AgentID, TenantID: "test-tenant", AuthSubject: "agent:" + request.AgentID},
			Credential: core.AgentCredentialGrant{
				AccessToken: "kcsp_agent_test.secret", TokenType: "Bearer", ExpiresAt: time.Now().UTC().Add(24 * time.Hour),
			},
		})
	}))
	t.Cleanup(server.Close)

	stateDirectory := t.TempDir()
	t.Setenv("KCSP_AGENT_SERVER_URL", server.URL)
	t.Setenv("KCSP_AGENT_TENANT_ID", "test-tenant")
	t.Setenv("KCSP_AGENT_ENROLLMENT_TOKEN", "kcsp_enroll_test.secret")
	t.Setenv("KCSP_AGENT_ID", "agent-enroll-only")
	t.Setenv("KCSP_AGENT_NAME", "Enrollment-only test agent")
	t.Setenv("KCSP_AGENT_STATE_DIR", stateDirectory)
	t.Setenv("KCSP_AGENT_ALLOW_INSECURE_HTTP", "true")
	t.Setenv("KCSP_AGENT_ENROLL_ONLY", "true")
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))

	if err := run(context.Background(), logger); err != nil {
		t.Fatalf("first enrollment-only run failed: %v", err)
	}
	credentialPath := filepath.Join(stateDirectory, "credential.json")
	if err := agentstate.ValidatePrivateFileSecurity(credentialPath); err != nil {
		t.Fatalf("credential security is not private: %v", err)
	}
	if err := run(context.Background(), logger); err != nil {
		t.Fatalf("credential reuse run failed: %v", err)
	}
	if requests.Load() != 1 {
		t.Fatalf("enrollment endpoint requests=%d, want 1", requests.Load())
	}
}
