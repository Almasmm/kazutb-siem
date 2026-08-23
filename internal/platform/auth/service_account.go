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

type ServiceAccountCredentialStore interface {
	ServiceAccountByTokenHash(context.Context, []byte) (core.ServiceAccount, error)
}

type ServiceAccountAuthenticator struct {
	store ServiceAccountCredentialStore
}

func NewServiceAccountAuthenticator(repository ServiceAccountCredentialStore) *ServiceAccountAuthenticator {
	return &ServiceAccountAuthenticator{store: repository}
}

func (a *ServiceAccountAuthenticator) Authenticate(request *http.Request) (Principal, error) {
	value := strings.TrimSpace(request.Header.Get("Authorization"))
	if !strings.HasPrefix(value, "Bearer ") {
		return Principal{}, ErrUnauthenticated
	}
	token := strings.TrimSpace(strings.TrimPrefix(value, "Bearer "))
	if !strings.HasPrefix(token, "kcsp_sat_") || len(token) > 512 {
		return Principal{}, ErrUnauthenticated
	}
	hash := sha256.Sum256([]byte(token))
	account, err := a.store.ServiceAccountByTokenHash(request.Context(), hash[:])
	if err != nil || account.RevokedAt != nil || !account.ExpiresAt.After(time.Now().UTC()) || !tenant.Valid(account.TenantID) || strings.TrimSpace(account.ID) == "" || len(account.Scopes) == 0 {
		return Principal{}, ErrUnauthenticated
	}
	permissions := PermissionsForScopes(account.Scopes)
	return Principal{
		ID: "service-account:" + account.ID, DisplayName: account.Name, Role: "Service Account",
		Permissions: permissions, AllowedTenants: map[string]bool{account.TenantID: true},
	}, nil
}
