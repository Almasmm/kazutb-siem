package httpapi

import (
	"context"
	"encoding/json"
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

const testLabBearer = "test-kcsp-lab-admin-token-32-bytes"

func newLabIsolationHandler(t *testing.T) http.Handler {
	t.Helper()
	repository := store.NewMemoryRepository()
	engine, err := pipeline.New(context.Background(), repository)
	if err != nil {
		t.Fatal(err)
	}
	return New(repository, engine, soc.New(repository), auth.NewDemoAuthenticatorWithLab(testLabBearer), slog.New(slog.NewTextHandler(io.Discard, nil)), func(context.Context) error { return nil })
}

func labRequest(handler http.Handler, method, path, bearer, tenantID string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, nil)
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	request.Header.Set("X-KCSP-Tenant-ID", tenantID)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func problemCode(t *testing.T, response *httptest.ResponseRecorder) string {
	t.Helper()
	var problem struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
		t.Fatalf("decode problem response: %v (body=%q)", err, response.Body.String())
	}
	return problem.Code
}

func TestLabCredentialAuthorizationMatrix(t *testing.T) {
	handler := newLabIsolationHandler(t)

	allowed := labRequest(handler, http.MethodGet, "/api/v1/events", testLabBearer, core.LabTenantID)
	if allowed.Code != http.StatusOK {
		t.Fatalf("lab read status = %d, want %d", allowed.Code, http.StatusOK)
	}

	for _, path := range []string{"/api/v1/events", "/api/v1/findings", "/api/v1/alerts", "/api/v1/incidents", "/api/v1/audit"} {
		t.Run("cross-tenant "+path, func(t *testing.T) {
			denied := labRequest(handler, http.MethodGet, path, testLabBearer, core.DefaultTenantID)
			if denied.Code != http.StatusForbidden || problemCode(t, denied) != "tenant_denied" {
				t.Fatalf("cross-tenant response = %d %s, want 403 tenant_denied", denied.Code, denied.Body.String())
			}
		})
	}

	privileged := labRequest(handler, http.MethodPost, "/api/v1/demo/reset", testLabBearer, core.LabTenantID)
	if privileged.Code != http.StatusForbidden || problemCode(t, privileged) != "permission_denied" {
		t.Fatalf("lab privileged response = %d %s, want 403 permission_denied", privileged.Code, privileged.Body.String())
	}

	for name, bearer := range map[string]string{"missing": "", "invalid": "not-a-real-token"} {
		t.Run(name+" bearer", func(t *testing.T) {
			denied := labRequest(handler, http.MethodGet, "/api/v1/events", bearer, core.LabTenantID)
			if denied.Code != http.StatusUnauthorized || problemCode(t, denied) != "authentication_required" {
				t.Fatalf("authentication response = %d %s, want 401 authentication_required", denied.Code, denied.Body.String())
			}
		})
	}

	platform := labRequest(handler, http.MethodPost, "/api/v1/demo/reset", "kcsp-demo-admin", core.DefaultTenantID)
	if platform.Code != http.StatusOK {
		t.Fatalf("platform admin privileged status = %d, want 200", platform.Code)
	}
}

func TestLabSessionReportsScopedIdentityAndTenant(t *testing.T) {
	response := labRequest(newLabIsolationHandler(t), http.MethodGet, "/api/v1/session", testLabBearer, core.LabTenantID)
	if response.Code != http.StatusOK {
		t.Fatalf("session status = %d", response.Code)
	}
	var session struct {
		Principal struct {
			ID   string `json:"id"`
			Role string `json:"role"`
		} `json:"principal"`
		Tenant struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"tenant"`
		Permissions []string `json:"permissions"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &session); err != nil {
		t.Fatal(err)
	}
	if session.Principal.ID != "svc-kcsp-lab-admin" || session.Principal.Role != "Lab Automation" {
		t.Fatalf("unexpected lab principal: %+v", session.Principal)
	}
	if session.Tenant.ID != core.LabTenantID || session.Tenant.Name != "KCSP Hyper-V Lab" {
		t.Fatalf("unexpected lab tenant: %+v", session.Tenant)
	}
	for _, permission := range session.Permissions {
		if permission == "*" || permission == "admin.tenants.manage" || permission == "licenses.install" {
			t.Fatalf("session exposed privileged permission %q", permission)
		}
	}
}
