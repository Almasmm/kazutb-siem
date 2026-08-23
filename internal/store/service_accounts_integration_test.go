package store_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/platform/auth"
	"github.com/kcsp/platform/internal/serviceaccount"
	"github.com/kcsp/platform/internal/store"
)

func TestPostgresServiceAccountLifecycleIsTenantBoundAndAudited(t *testing.T) {
	databaseURL := os.Getenv("KCSP_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("KCSP_TEST_DATABASE_URL is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tenantID := strings.ReplaceAll("service-account-"+core.NewID("tenant"), "_", "-")
	repository, err := store.OpenPostgres(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	if err := repository.EnsureTenant(ctx, tenantID, "Service Account Test"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_ = repository.ResetTenant(cleanupCtx, tenantID)
	})
	actor := auth.Principal{ID: "tenant-admin", Permissions: map[string]bool{"siem.events.read": true}, AllowedTenants: map[string]bool{tenantID: true}}
	service := serviceaccount.NewService(repository, serviceaccount.Config{DefaultTTL: time.Hour, MaximumTTL: 24 * time.Hour})
	issued, err := service.Create(ctx, tenantID, actor, serviceaccount.CreateRequest{Name: "Reporting Export", Scopes: []string{"siem.events.read"}})
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte(issued.AccessToken))
	account, err := repository.ServiceAccountByTokenHash(ctx, hash[:])
	if err != nil || account.TenantID != tenantID || account.LastUsedAt == nil {
		t.Fatalf("authenticate service account: account=%+v err=%v", account, err)
	}
	replacement, err := service.Rotate(ctx, tenantID, account.ID, actor, serviceaccount.RotateRequest{})
	if err != nil || replacement.ServiceAccount.TokenVersion != 2 {
		t.Fatalf("rotate service account: issue=%+v err=%v", replacement, err)
	}
	if _, err := repository.ServiceAccountByTokenHash(ctx, hash[:]); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("old service token remained valid: %v", err)
	}
	if _, err := service.Revoke(ctx, tenantID, account.ID, actor); err != nil {
		t.Fatal(err)
	}
	replacementHash := sha256.Sum256([]byte(replacement.AccessToken))
	if _, err := repository.ServiceAccountByTokenHash(ctx, replacementHash[:]); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("revoked service token remained valid: %v", err)
	}
	audit, err := repository.ListAudit(ctx, tenantID, 10)
	if err != nil || len(audit) < 3 {
		t.Fatalf("service account audit entries=%d err=%v", len(audit), err)
	}
	valid, err := repository.VerifyAudit(ctx, tenantID)
	if err != nil || !valid {
		t.Fatalf("service account audit chain valid=%v err=%v", valid, err)
	}
}
