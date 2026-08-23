package auth

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/kcsp/platform/internal/core"
)

type agentCredentialStoreStub struct {
	hash       []byte
	credential core.AgentCredential
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
