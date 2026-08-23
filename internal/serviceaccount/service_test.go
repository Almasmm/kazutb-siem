package serviceaccount

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/kcsp/platform/internal/platform/auth"
	"github.com/kcsp/platform/internal/store"
)

func TestServiceAccountLifecycleAndAuthentication(t *testing.T) {
	t.Parallel()
	repository := store.NewMemoryRepository()
	tenantID := "university-test"
	actor := auth.Principal{
		ID: "tenant-admin", Permissions: map[string]bool{"siem.events.read": true, "siem.hunt.execute": true},
		AllowedTenants: map[string]bool{tenantID: true},
	}
	now := time.Date(2026, 8, 23, 7, 0, 0, 0, time.UTC)
	service := NewService(repository, Config{Now: func() time.Time { return now }, DefaultTTL: time.Hour, MaximumTTL: 24 * time.Hour})
	issued, err := service.Create(context.Background(), tenantID, actor, CreateRequest{Name: "Hunt Automation", Scopes: []string{"siem.events.read", "siem.hunt.execute"}})
	if err != nil || issued.AccessToken == "" || issued.ServiceAccount.TokenVersion != 1 {
		t.Fatalf("create service account: issue=%+v err=%v", issued, err)
	}
	authenticator := auth.NewServiceAccountAuthenticatorWithClock(repository, func() time.Time { return now })
	request, _ := http.NewRequest(http.MethodGet, "https://soc.test/api/v1/events", nil)
	request.Header.Set("Authorization", "Bearer "+issued.AccessToken)
	principal, err := authenticator.Authenticate(request)
	if err != nil || !principal.Can("siem.events.read") || !principal.Can("siem.hunt.read") || principal.Can("siem.events.ingest") || !principal.CanAccessTenant(tenantID) {
		t.Fatalf("authenticate scoped token: principal=%+v err=%v", principal, err)
	}
	replacement, err := service.Rotate(context.Background(), tenantID, issued.ServiceAccount.ID, actor, RotateRequest{ExpiresInSeconds: 7200})
	if err != nil || replacement.AccessToken == issued.AccessToken || replacement.ServiceAccount.TokenVersion != 2 {
		t.Fatalf("rotate service account: replacement=%+v err=%v", replacement, err)
	}
	if _, err := authenticator.Authenticate(request); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("rotated token remained valid: %v", err)
	}
	request.Header.Set("Authorization", "Bearer "+replacement.AccessToken)
	if _, err := authenticator.Authenticate(request); err != nil {
		t.Fatalf("replacement token is invalid: %v", err)
	}
	if _, err := service.Revoke(context.Background(), tenantID, issued.ServiceAccount.ID, actor); err != nil {
		t.Fatal(err)
	}
	if _, err := authenticator.Authenticate(request); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("revoked token remained valid: %v", err)
	}
	audit, err := repository.ListAudit(context.Background(), tenantID, 10)
	if err != nil || len(audit) != 3 {
		t.Fatalf("service account audit: entries=%+v err=%v", audit, err)
	}
	_ = sha256.Size
}

func TestServiceAccountRejectsPrivilegeEscalation(t *testing.T) {
	t.Parallel()
	repository := store.NewMemoryRepository()
	actor := auth.Principal{ID: "admin", Permissions: map[string]bool{"*": true}, AllowedTenants: map[string]bool{"university-test": true}}
	service := NewService(repository, Config{})
	for _, scope := range []string{"*", "platform.service_accounts.write", "soar.actions.approve", "not.a.permission"} {
		if _, err := service.Create(context.Background(), "university-test", actor, CreateRequest{Name: "Unsafe Token", Scopes: []string{scope}}); !errors.Is(err, ErrScopeDenied) {
			t.Fatalf("unsafe scope %q was accepted: %v", scope, err)
		}
	}
}
