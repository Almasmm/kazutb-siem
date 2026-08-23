package auth

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kcsp/platform/internal/core"
)

type agentCredentialStoreStub struct {
	hash       []byte
	credential core.AgentCredential
}

type defenseInDepthCredentialStore struct {
	credential core.AgentCredential
}

func (s defenseInDepthCredentialStore) AgentCredentialByHash(context.Context, []byte) (core.AgentCredential, error) {
	return s.credential, nil
}

func TestAgentAuthenticatorRejectsInvalidStoredCredential(t *testing.T) {
	now := time.Now().UTC()
	revokedAt := now.Add(-time.Minute)
	valid := core.AgentCredential{
		TenantID:    "university-kulazhanov",
		CollectorID: "collector-windows-01",
		AuthSubject: "agent:collector-windows-01",
		ExpiresAt:   now.Add(time.Hour),
	}
	tests := map[string]core.AgentCredential{
		"expired":            func() core.AgentCredential { value := valid; value.ExpiresAt = now.Add(-time.Minute); return value }(),
		"revoked":            func() core.AgentCredential { value := valid; value.RevokedAt = &revokedAt; return value }(),
		"invalid tenant":     func() core.AgentCredential { value := valid; value.TenantID = "../tenant"; return value }(),
		"empty collector":    func() core.AgentCredential { value := valid; value.CollectorID = " "; return value }(),
		"empty auth subject": func() core.AgentCredential { value := valid; value.AuthSubject = " "; return value }(),
	}

	for name, credential := range tests {
		t.Run(name, func(t *testing.T) {
			authenticator := NewAgentAuthenticator(defenseInDepthCredentialStore{credential: credential})
			request := httptest.NewRequest(http.MethodPost, "https://kcsp.local/api/v1/ingest/events", nil)
			request.Header.Set("Authorization", "Bearer kcsp_agent_test-credential")
			if _, err := authenticator.Authenticate(request); !errors.Is(err, ErrUnauthenticated) {
				t.Fatalf("expected invalid credential to be rejected, got %v", err)
			}
		})
	}
}

func (s agentCredentialStoreStub) AgentCredentialByHash(_ context.Context, hash []byte) (core.AgentCredential, error) {
	if string(hash) != string(s.hash) {
		return core.AgentCredential{}, errors.New("not found")
	}
	return s.credential, nil
}

func TestAgentAuthenticatorScopesMachineCredential(t *testing.T) {
	token := "kcsp_agent_cred_test.secret"
	hash := sha256.Sum256([]byte(token))
	authenticator := NewAgentAuthenticator(agentCredentialStoreStub{hash: hash[:], credential: core.AgentCredential{
		ID: "cred-test", TenantID: "tenant-a", CollectorID: "agent-01", AuthSubject: "agent:agent-01", ExpiresAt: time.Now().Add(time.Hour),
	}})
	request, _ := http.NewRequest(http.MethodPost, "http://kcsp.local/api/v1/ingest/events", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	principal, err := authenticator.Authenticate(request)
	if err != nil {
		t.Fatal(err)
	}
	if principal.ID != "agent:agent-01" || !principal.Can("siem.events.ingest") || principal.Can("siem.events.read") || !principal.CanAccessTenant("tenant-a") || principal.CanAccessTenant("tenant-b") {
		t.Fatalf("unexpected machine principal: %+v", principal)
	}
}

func TestChainedAuthenticatorFallsBackWithoutBroadeningAgentPermissions(t *testing.T) {
	request, _ := http.NewRequest(http.MethodGet, "http://kcsp.local/api/v1/events", nil)
	request.Header.Set("Authorization", "Bearer kcsp-demo-l1")
	chain := NewChainedAuthenticator(NewAgentAuthenticator(agentCredentialStoreStub{}), NewDemoAuthenticator())
	principal, err := chain.Authenticate(request)
	if err != nil || principal.ID != "user-soc-l1" {
		t.Fatalf("demo fallback failed: principal=%+v err=%v", principal, err)
	}
}
