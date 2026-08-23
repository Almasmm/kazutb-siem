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
	ServiceAccountByTokenHash(context.Context, []byte, time.Time) (core.ServiceAccount, error)
}

type ServiceAccountAuthenticator struct {
	store ServiceAccountCredentialStore
	now   func() time.Time
}

func NewServiceAccountAuthenticator(repository ServiceAccountCredentialStore) *ServiceAccountAuthenticator {
	return NewServiceAccountAuthenticatorWithClock(repository, func() time.Time { return time.Now().UTC() })
}

func NewServiceAccountAuthenticatorWithClock(repository ServiceAccountCredentialStore, now func() time.Time) *ServiceAccountAuthenticator {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &ServiceAccountAuthenticator{store: repository, now: now}
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
	checkedAt := a.now().UTC()
	account, err := a.store.ServiceAccountByTokenHash(request.Context(), hash[:], checkedAt)
	if err != nil || account.RevokedAt != nil || !account.ExpiresAt.After(checkedAt) || !tenant.Valid(account.TenantID) || strings.TrimSpace(account.ID) == "" || len(account.Scopes) == 0 {
		return Principal{}, ErrUnauthenticated
	}
	permissions := PermissionsForScopes(account.Scopes)
	return Principal{
		ID: "service-account:" + account.ID, DisplayName: account.Name, Role: "Service Account",
		Permissions: permissions, AllowedTenants: map[string]bool{account.TenantID: true},
	}, nil
}
