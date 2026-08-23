package observability

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestReadinessHandlerFailsClosedAndChecksDependencies(t *testing.T) {
	registry := &Registry{}
	handler := HandlerFor(registry)

	request := func() *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/health/ready", nil))
		return recorder
	}

	recorder := request()
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status before startup = %d, want %d", recorder.Code, http.StatusServiceUnavailable)
	}

	registry.SetReadinessCheck(func(context.Context) error { return nil })
	registry.MarkReady()
	recorder = request()
	if recorder.Code != http.StatusOK {
		t.Fatalf("ready status = %d, want %d", recorder.Code, http.StatusOK)
	}

	registry.SetReadinessCheck(func(context.Context) error {
		return errors.New("database password must not leak")
	})
	recorder = request()
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("dependency failure status = %d, want %d", recorder.Code, http.StatusServiceUnavailable)
	}
	if strings.Contains(recorder.Body.String(), "database password") {
		t.Fatal("readiness response leaked dependency error")
	}

	registry.MarkNotReady()
	recorder = request()
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status after shutdown = %d, want %d", recorder.Code, http.StatusServiceUnavailable)
	}
}
