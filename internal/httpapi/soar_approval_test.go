package httpapi

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/pipeline"
	"github.com/kcsp/platform/internal/platform/auth"
	"github.com/kcsp/platform/internal/soar"
	"github.com/kcsp/platform/internal/soc"
	"github.com/kcsp/platform/internal/store"
)

type approvalHTTPStore struct {
	commands []core.SOARApprovalCommand
	err      error
}

func (s *approvalHTTPStore) CreateSOARPlaybook(context.Context, core.SOARPlaybook, core.SOARPlaybookVersion) (core.SOARPlaybookDetails, error) {
	return core.SOARPlaybookDetails{}, nil
}
func (s *approvalHTTPStore) CreateSOARPlaybookVersion(context.Context, string, string, string, core.SOARPlaybookSpec, core.SOARValidationReport) (core.SOARPlaybookVersion, error) {
	return core.SOARPlaybookVersion{}, nil
}
func (s *approvalHTTPStore) GetSOARPlaybook(context.Context, string, string) (core.SOARPlaybookDetails, error) {
	return core.SOARPlaybookDetails{}, nil
}
func (s *approvalHTTPStore) ListSOARPlaybooks(context.Context, string) ([]core.SOARPlaybook, error) {
	return nil, nil
}
func (s *approvalHTTPStore) SaveSOARValidation(context.Context, string, string, int, core.SOARValidationReport) (core.SOARPlaybookVersion, error) {
	return core.SOARPlaybookVersion{}, nil
}
func (s *approvalHTTPStore) PublishSOARPlaybookVersion(context.Context, string, string, int, string) (core.SOARPlaybookDetails, error) {
	return core.SOARPlaybookDetails{}, nil
}
func (s *approvalHTTPStore) DisableSOARPlaybook(context.Context, string, string, string) (core.SOARPlaybook, error) {
	return core.SOARPlaybook{}, nil
}
func (s *approvalHTTPStore) CreateSOARExecution(context.Context, core.SOARExecution, []core.SOARNode) (core.SOARExecution, bool, error) {
	return core.SOARExecution{}, false, nil
}
func (s *approvalHTTPStore) GetSOARExecution(context.Context, string, string) (core.SOARExecution, error) {
	return core.SOARExecution{}, nil
}
func (s *approvalHTTPStore) ListSOARExecutions(context.Context, string, core.SOARExecutionFilter) ([]core.SOARExecution, error) {
	return nil, nil
}
func (s *approvalHTTPStore) ListSOARApprovals(context.Context, string, core.SOARApprovalFilter) ([]core.SOARApproval, error) {
	return nil, nil
}
func (s *approvalHTTPStore) CompleteSOARManualTask(context.Context, string, string, string, map[string]interface{}) (core.SOARExecution, error) {
	return core.SOARExecution{}, nil
}
func (s *approvalHTTPStore) ListSOARActionAttempts(context.Context, string, string, int) ([]core.SOARActionAttempt, error) {
	return nil, nil
}
func (s *approvalHTTPStore) DecideSOARApproval(_ context.Context, tenantID, approvalID, _ string, command core.SOARApprovalCommand) (core.SOARApproval, error) {
	if s.err != nil {
		return core.SOARApproval{}, s.err
	}
	s.commands = append(s.commands, command)
	status := core.ApprovalStatusApproved
	if command.Decision == core.ApprovalDecisionReject {
		status = core.ApprovalStatusRejected
	}
	return core.SOARApproval{ID: approvalID, TenantID: tenantID, ExecutionID: "run-1", NodeExecutionID: "node-1", Status: status, Version: command.Version + 1}, nil
}

func newSOARApprovalHTTPStack(t *testing.T, runtimeStore *approvalHTTPStore) (*store.Memory, http.Handler) {
	t.Helper()
	memory := store.NewMemory()
	repository := store.WrapMemory(memory)
	engine, err := pipeline.New(context.Background(), repository)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewWithConfig(repository, engine, soc.New(repository), auth.NewDemoAuthenticator(), slog.New(slog.NewTextHandler(io.Discard, nil)), nil,
		Config{Profile: "test", AuthMode: "demo", AllowDirectIngest: true, SOARService: soar.NewService(runtimeStore, nil)})
	return memory, handler
}

func approvalHTTPRequest(body, token, tenant string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "/api/v1/soar/approvals/sap-1/decisions", bytes.NewBufferString(body))
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	request.Header.Set("X-KCSP-Tenant-ID", tenant)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Request-ID", "req-approval-test")
	request.RemoteAddr = "192.0.2.50:4444"
	return request
}

func TestSOARApprovalHTTPAcceptsCanonicalCommands(t *testing.T) {
	runtimeStore := &approvalHTTPStore{}
	_, handler := newSOARApprovalHTTPStack(t, runtimeStore)
	for _, decision := range []string{"APPROVE", "REJECT"} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, approvalHTTPRequest(`{"decision":"`+decision+`","reason":"Reviewed by SOC","version":4}`, "kcsp-demo-soar-engineer", "university-kulazhanov"))
		if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"version":5`) {
			t.Fatalf("%s status=%d body=%s", decision, recorder.Code, recorder.Body.String())
		}
	}
	if len(runtimeStore.commands) != 2 || runtimeStore.commands[0].Decision != core.ApprovalDecisionApprove || runtimeStore.commands[1].Decision != core.ApprovalDecisionReject {
		t.Fatalf("unexpected canonical commands: %+v", runtimeStore.commands)
	}
}

func TestSOARApprovalHTTPRejectsInvalidPayloads(t *testing.T) {
	runtimeStore := &approvalHTTPStore{}
	_, handler := newSOARApprovalHTTPStack(t, runtimeStore)
	tests := []struct {
		body   string
		status int
	}{
		{`{"decision":"APPROVED","reason":"Reviewed","version":1}`, 422},
		{`{"decision":"REJECTED","reason":"Reviewed","version":1}`, 422},
		{`{"decision":"approve","reason":"Reviewed","version":1}`, 422},
		{`{"decision":"APPROVE ","reason":"Reviewed","version":1}`, 422},
		{`{"decision":"","reason":"Reviewed","version":1}`, 422},
		{`{"decision":null,"reason":"Reviewed","version":1}`, 422},
		{`{"decision":"REJECT","reason":"","version":1}`, 422},
		{`{"decision":"APPROVE","reason":"Reviewed","version":0}`, 422},
		{`{"decision":true,"reason":"Reviewed","version":1}`, 400},
		{`{"decision":"APPROVE","reason":"Reviewed","version":1,"tenant_id":"other"}`, 400},
		{`{"decision":"APPROVE"`, 400},
	}
	for _, test := range tests {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, approvalHTTPRequest(test.body, "kcsp-demo-soar-engineer", "university-kulazhanov"))
		if recorder.Code != test.status {
			t.Fatalf("body=%s status=%d want=%d response=%s", test.body, recorder.Code, test.status, recorder.Body.String())
		}
	}
	if len(runtimeStore.commands) != 0 {
		t.Fatalf("invalid payload reached runtime: %+v", runtimeStore.commands)
	}
}

func TestSOARApprovalHTTPEnforcesPermissionTenantVersionAndAudit(t *testing.T) {
	runtimeStore := &approvalHTTPStore{}
	memory, handler := newSOARApprovalHTTPStack(t, runtimeStore)
	for _, test := range []struct {
		token, tenant string
		status        int
	}{
		{"", "university-kulazhanov", 401},
		{"kcsp-demo-l2", "university-kulazhanov", 403},
		{"kcsp-demo-soar-engineer", "other-tenant", 403},
	} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, approvalHTTPRequest(`{"decision":"APPROVE","reason":"Reviewed","version":1}`, test.token, test.tenant))
		if recorder.Code != test.status {
			t.Fatalf("token=%q tenant=%q status=%d body=%s", test.token, test.tenant, recorder.Code, recorder.Body.String())
		}
	}
	if len(memory.ListAudit("university-kulazhanov", 20)) < 3 {
		t.Fatalf("approval denials were not tenant-audited: %+v", memory.ListAudit("university-kulazhanov", 20))
	}

	runtimeStore.err = soar.ErrApprovalVersionConflict
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, approvalHTTPRequest(`{"decision":"APPROVE","reason":"Reviewed","version":1}`, "kcsp-demo-soar-engineer", "university-kulazhanov"))
	if recorder.Code != http.StatusConflict || !strings.Contains(recorder.Body.String(), "approval_version_conflict") {
		t.Fatalf("stale status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	entries := memory.ListAudit("university-kulazhanov", 20)
	if entries[0].Action != "soar.approval.decision_rejected" || entries[0].Metadata["reason_code"] != "VERSION_CONFLICT" {
		t.Fatalf("stale decision audit missing: %+v", entries[0])
	}
}
