package auth

import (
	"context"
	"crypto/sha256"
	"net/http"
	"strings"
	"time"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/platform/tenant"
)

type AgentCredentialStore interface {
	AgentCredentialByHash(context.Context, []byte) (core.AgentCredential, error)
}

type AgentAuthenticator struct {
	store AgentCredentialStore
}

func NewAgentAuthenticator(repository AgentCredentialStore) *AgentAuthenticator {
	return &AgentAuthenticator{store: repository}
}

func (a *AgentAuthenticator) Authenticate(request *http.Request) (Principal, error) {
	value := strings.TrimSpace(request.Header.Get("Authorization"))
	if !strings.HasPrefix(value, "Bearer ") {
		return Principal{}, ErrUnauthenticated
	}
	token := strings.TrimSpace(strings.TrimPrefix(value, "Bearer "))
	if !strings.HasPrefix(token, "kcsp_agent_") || len(token) > 512 {
		return Principal{}, ErrUnauthenticated
	}
	hash := sha256.Sum256([]byte(token))
	credential, err := a.store.AgentCredentialByHash(request.Context(), hash[:])
	if err != nil {
		return Principal{}, ErrUnauthenticated
	}
	if credential.RevokedAt != nil || !credential.ExpiresAt.After(time.Now().UTC()) || !tenant.Valid(credential.TenantID) || strings.TrimSpace(credential.CollectorID) == "" || strings.TrimSpace(credential.AuthSubject) == "" {
		return Principal{}, ErrUnauthenticated
	}
	return Principal{
		ID: credential.AuthSubject, DisplayName: credential.CollectorID, Role: "Service Account",
		Permissions:    map[string]bool{"siem.events.ingest": true, "platform.collectors.heartbeat": true},
		AllowedTenants: map[string]bool{credential.TenantID: true},
	}, nil
}

type RequestAuthenticator interface {
	Authenticate(*http.Request) (Principal, error)
}

type ChainedAuthenticator struct {
	authenticators []RequestAuthenticator
}

func NewChainedAuthenticator(authenticators ...RequestAuthenticator) *ChainedAuthenticator {
	return &ChainedAuthenticator{authenticators: authenticators}
}

func (a *ChainedAuthenticator) Authenticate(request *http.Request) (Principal, error) {
	for _, authenticator := range a.authenticators {
		if authenticator == nil {
			continue
		}
		principal, err := authenticator.Authenticate(request)
		if err == nil {
			return principal, nil
		}
	}
	return Principal{}, ErrUnauthenticated
}
