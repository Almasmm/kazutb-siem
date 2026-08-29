package httpapi

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/pipeline"
	"github.com/kcsp/platform/internal/platform/auth"
	"github.com/kcsp/platform/internal/soc"
	"github.com/kcsp/platform/internal/store"
)

func TestLabCredentialCannotReadUniversityTenant(t *testing.T) {
	repository := store.NewMemoryRepository()
	engine, err := pipeline.New(context.Background(), repository)
	if err != nil {
		t.Fatal(err)
	}
	handler := New(repository, engine, soc.New(repository), auth.NewDemoAuthenticatorWithLab("test-kcsp-lab-admin-token-32-bytes"), slog.New(slog.NewTextHandler(io.Discard, nil)), nil)

	request := httptest.NewRequest(http.MethodGet, "/api/v1/events", nil)
	request.Header.Set("Authorization", "Bearer test-kcsp-lab-admin-token-32-bytes")
	request.Header.Set("X-KCSP-Tenant-ID", core.DefaultTenantID)
	denied := httptest.NewRecorder()
	handler.ServeHTTP(denied, request)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("university read status = %d, want %d", denied.Code, http.StatusForbidden)
	}

	request = httptest.NewRequest(http.MethodGet, "/api/v1/events", nil)
	request.Header.Set("Authorization", "Bearer test-kcsp-lab-admin-token-32-bytes")
	request.Header.Set("X-KCSP-Tenant-ID", core.LabTenantID)
	allowed := httptest.NewRecorder()
	handler.ServeHTTP(allowed, request)
	if allowed.Code != http.StatusOK {
		t.Fatalf("lab read status = %d, want %d", allowed.Code, http.StatusOK)
	}
}
