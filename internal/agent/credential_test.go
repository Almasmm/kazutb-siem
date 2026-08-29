package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kcsp/platform/internal/core"
)

func TestCredentialManagerEnrollsPersistsReloadsAndRotates(t *testing.T) {
	directory := t.TempDir()
	oldToken := "kcsp_agent_cred_old.secret"
	newToken := "kcsp_agent_cred_new.secret"
	expires := time.Now().UTC().Add(2 * time.Hour)
	enrollCalls := 0
	rotateCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/api/v1/agent-enrollment":
			enrollCalls++
			var input core.AgentEnrollmentRequest
			if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
				t.Fatal(err)
			}
			if input.EnrollmentToken != "kcsp_enroll_test.secret" || input.AgentID != "agent-test-01" || input.Platform == "" {
				t.Fatalf("unexpected enrollment request: %+v", input)
			}
			response.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(response).Encode(core.AgentEnrollmentResponse{
				Collector:  core.Collector{ID: input.AgentID},
				Credential: core.AgentCredentialGrant{AccessToken: oldToken, TokenType: "Bearer", ExpiresAt: expires},
			})
		case "/api/v1/agent-credentials/rotate":
			rotateCalls++
			if request.Header.Get("Authorization") != "Bearer "+oldToken || request.Header.Get("X-KCSP-Tenant-ID") != "tenant-a" {
				t.Fatalf("rotation identity missing: %v", request.Header)
			}
			_ = json.NewEncoder(response).Encode(core.AgentCredentialGrant{AccessToken: newToken, TokenType: "Bearer", ExpiresAt: time.Now().UTC().Add(30 * 24 * time.Hour)})
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	manager, err := OpenCredentialManager(CredentialManagerConfig{
		ServerURL: server.URL, TenantID: "tenant-a", EnrollmentToken: "kcsp_enroll_test.secret",
		StateDirectory: directory, AgentID: "agent-test-01", AgentName: "Test Agent", AgentVersion: "0.4.0", AllowInsecure: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	grant, err := manager.Ensure(context.Background())
	if err != nil || grant.AccessToken != oldToken || enrollCalls != 1 {
		t.Fatalf("enrollment failed: grant=%+v calls=%d err=%v", grant, enrollCalls, err)
	}
	if !manager.ShouldRotate(time.Now().UTC(), 3*time.Hour) {
		t.Fatal("credential inside rotation window was not selected")
	}
	credentialPath := filepath.Join(directory, "credential.json")
	body, err := os.ReadFile(credentialPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "kcsp_enroll_test") {
		t.Fatal("bootstrap enrollment token was persisted")
	}
	if err := ValidatePrivateFileSecurity(credentialPath); err != nil {
		t.Fatalf("credential security is not private: %v", err)
	}
	reloaded, err := OpenCredentialManager(CredentialManagerConfig{ServerURL: server.URL, TenantID: "tenant-a", StateDirectory: directory, AllowInsecure: true})
	if err != nil {
		t.Fatal(err)
	}
	defer reloaded.Close()
	loaded, err := reloaded.Ensure(context.Background())
	if err != nil || loaded.AccessToken != oldToken || enrollCalls != 1 {
		t.Fatalf("persisted credential was not reused: grant=%+v calls=%d err=%v", loaded, enrollCalls, err)
	}
	rotated, err := reloaded.Rotate(context.Background())
	if err != nil || rotated.AccessToken != newToken || rotateCalls != 1 {
		t.Fatalf("rotation failed: grant=%+v calls=%d err=%v", rotated, rotateCalls, err)
	}
	afterRotation, err := reloaded.loadCredential()
	if err != nil || afterRotation.AccessToken != newToken {
		t.Fatalf("rotated credential was not persisted: credential=%+v err=%v", afterRotation, err)
	}
}

func TestCredentialManagerRejectsUnprotectedHTTP(t *testing.T) {
	if _, err := OpenCredentialManager(CredentialManagerConfig{
		ServerURL: "http://soc.example.edu", TenantID: "tenant-a", StateDirectory: t.TempDir(),
	}); err == nil {
		t.Fatal("expected insecure enrollment endpoint to be rejected")
	}
}
