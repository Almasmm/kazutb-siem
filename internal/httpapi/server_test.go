package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/pipeline"
	"github.com/kcsp/platform/internal/platform/auth"
	"github.com/kcsp/platform/internal/soc"
	"github.com/kcsp/platform/internal/store"
)

func TestEndToEndIngestReadAndTenantDenial(t *testing.T) {
	memory := store.NewMemory()
	engine := pipeline.New(memory)
	service := soc.New(memory)
	handler := New(memory, engine, service, auth.NewDemoAuthenticator(), slog.New(slog.NewTextHandler(io.Discard, nil)), nil)

	payload := []byte(`{
		"event_id":"http-e2e-1","category":"process_activity","activity_name":"Process created",
		"source":{"vendor":"Microsoft","product":"Sysmon","type":"endpoint"},
		"user":{"name":"KUTB\\\\admin","is_privileged":true},
		"device":{"hostname":"dc-01","criticality":5},
		"process":{"name":"powershell.exe","command_line":"powershell.exe -EncodedCommand SQBFAFgA"}
	}`)
	ingest := httptest.NewRequest(http.MethodPost, "/api/v1/events", bytes.NewReader(payload))
	ingest.Header.Set("Authorization", "Bearer kcsp-demo-collector")
	ingest.Header.Set("X-KCSP-Tenant-ID", "university-kulazhanov")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, ingest)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("ingest status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	list := httptest.NewRequest(http.MethodGet, "/api/v1/alerts", nil)
	list.Header.Set("Authorization", "Bearer kcsp-demo-l2")
	list.Header.Set("X-KCSP-Tenant-ID", "university-kulazhanov")
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, list)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), pipeline.PowerShellRuleID) {
		t.Fatalf("alerts status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	crossTenant := httptest.NewRequest(http.MethodGet, "/api/v1/alerts", nil)
	crossTenant.Header.Set("Authorization", "Bearer kcsp-demo-l2")
	crossTenant.Header.Set("X-KCSP-Tenant-ID", "another-tenant")
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, crossTenant)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("cross-tenant request status=%d", recorder.Code)
	}

	unauthenticated := httptest.NewRequest(http.MethodGet, "/api/v1/alerts", nil)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, unauthenticated)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated request status=%d", recorder.Code)
	}
}

func TestOptimisticConcurrencyReturnsPreconditionFailed(t *testing.T) {
	memory := store.NewMemory()
	engine := pipeline.New(memory)
	service := soc.New(memory)
	handler := New(memory, engine, service, auth.NewDemoAuthenticator(), slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	result, err := engine.Ingest(context.Background(), "university-kulazhanov", mustEvent(t, `{
		"event_id":"evt-version","category":"process_activity",
		"source":{"vendor":"Microsoft","product":"Sysmon","type":"endpoint"},
		"process":{"name":"powershell.exe","command_line":"Invoke-WebRequest https://example.invalid"}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	requestBody := bytes.NewBufferString(`{"status":"ACKNOWLEDGED","version":99}`)
	request := httptest.NewRequest(http.MethodPatch, "/api/v1/alerts/"+result.Alerts[0].ID, requestBody)
	request.Header.Set("Authorization", "Bearer kcsp-demo-l2")
	request.Header.Set("X-KCSP-Tenant-ID", "university-kulazhanov")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusPreconditionFailed {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestBodyLimitsAndMutationMassAssignmentProtection(t *testing.T) {
	memory := store.NewMemory()
	engine := pipeline.New(memory)
	service := soc.New(memory)
	handler := New(memory, engine, service, auth.NewDemoAuthenticator(), slog.New(slog.NewTextHandler(io.Discard, nil)), nil)

	oversized := httptest.NewRequest(http.MethodPost, "/api/v1/events", strings.NewReader(`{"category":"`+strings.Repeat("x", (1<<20)+32)+`"}`))
	oversized.Header.Set("Authorization", "Bearer kcsp-demo-collector")
	oversized.Header.Set("X-KCSP-Tenant-ID", "university-kulazhanov")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, oversized)
	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	result, err := engine.Ingest(context.Background(), "university-kulazhanov", mustEvent(t, `{
		"event_id":"evt-mass-assignment","category":"process_activity",
		"source":{"vendor":"Microsoft","product":"Sysmon","type":"endpoint"},
		"process":{"name":"powershell.exe","command_line":"Invoke-WebRequest https://example.invalid"}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	unknownField := httptest.NewRequest(http.MethodPatch, "/api/v1/alerts/"+result.Alerts[0].ID, strings.NewReader(`{"status":"ACKNOWLEDGED","tenant_id":"another-tenant"}`))
	unknownField.Header.Set("Authorization", "Bearer kcsp-demo-l2")
	unknownField.Header.Set("X-KCSP-Tenant-ID", "university-kulazhanov")
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, unknownField)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("unknown mutation field status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func mustEvent(t *testing.T, value string) (event core.CanonicalEvent) {
	t.Helper()
	if err := json.Unmarshal([]byte(value), &event); err != nil {
		t.Fatal(err)
	}
	return event
}
