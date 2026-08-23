package cases

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/store"
)

func TestCaseLifecycleCommandsPreserveInvestigationHistory(t *testing.T) {
	repository := newCaseRepository()
	repository.incidents["tenant-a/inc-1"] = core.Incident{ID: "inc-1", TenantID: "tenant-a", Severity: core.SeverityHigh}
	service := NewService(repository)
	ctx := context.Background()
	item, duplicate, err := service.Create(ctx, "tenant-a", "analyst-a", CreateInput{Title: "PowerShell compromise", IncidentIDs: []string{"inc-1"}, RequestID: "request-1"})
	if err != nil || duplicate || item.Status != core.CaseStatusOpen || item.Severity != core.SeverityHigh || len(item.Participants) != 1 {
		t.Fatalf("create case: item=%+v duplicate=%v err=%v", item, duplicate, err)
	}
	duplicateItem, duplicate, err := service.Create(ctx, "tenant-a", "analyst-a", CreateInput{Title: "PowerShell compromise", IncidentIDs: []string{"inc-1"}, RequestID: "request-1"})
	if err != nil || !duplicate || duplicateItem.ID != item.ID {
		t.Fatalf("idempotent case create: item=%+v duplicate=%v err=%v", duplicateItem, duplicate, err)
	}
	item, err = service.AddTask(ctx, "tenant-a", item.ID, "analyst-a", "request-2", TaskInput{Title: "Collect triage package", Assignee: "analyst-b", Version: item.Version})
	if err != nil || len(item.Tasks) != 1 || item.Tasks[0].Status != core.CaseTaskOpen {
		t.Fatalf("add task: item=%+v err=%v", item, err)
	}
	item, err = service.UpdateTask(ctx, "tenant-a", item.ID, item.Tasks[0].ID, "analyst-b", "request-3", TaskPatch{Status: core.CaseTaskDone, Version: item.Version})
	if err != nil || item.Tasks[0].CompletedAt == nil || item.Tasks[0].CompletedBy != "analyst-b" {
		t.Fatalf("complete task: item=%+v err=%v", item, err)
	}
	item, err = service.AddComment(ctx, "tenant-a", item.ID, "analyst-b", "Host isolated and evidence sealed", "request-4", item.Version)
	if err != nil || len(item.Comments) != 1 {
		t.Fatalf("add comment: item=%+v err=%v", item, err)
	}
	item, err = service.AddObservable(ctx, "tenant-a", item.ID, "analyst-b", "request-5", ObservableInput{Type: "HASH", Value: strings.Repeat("a", 64), Source: "evd-1"}, item.Version)
	if err != nil || len(item.Observables) != 1 {
		t.Fatalf("add observable: item=%+v err=%v", item, err)
	}
	item, err = service.Update(ctx, "tenant-a", item.ID, "analyst-b", Patch{Status: core.CaseStatusInvestigation, Version: item.Version, RequestID: "request-6"})
	if err != nil || item.Status != core.CaseStatusInvestigation {
		t.Fatalf("advance case: item=%+v err=%v", item, err)
	}
	if _, err := service.Update(ctx, "tenant-a", item.ID, "analyst-b", Patch{Status: core.CaseStatusClosed, Version: item.Version}); !errors.Is(err, ErrClosureDetails) {
		t.Fatalf("expected closure validation, got %v", err)
	}
	item, err = service.Update(ctx, "tenant-a", item.ID, "analyst-b", Patch{Status: core.CaseStatusClosed, ClosureSummary: "Contained, credential reset complete", Version: item.Version, RequestID: "request-7"})
	if err != nil || item.ClosedAt == nil || len(item.History) < 6 {
		t.Fatalf("close case: item=%+v err=%v", item, err)
	}
	if len(repository.audits) < 7 {
		t.Fatalf("expected audited commands, got %d", len(repository.audits))
	}
}

func TestCaseTenantAndVersionIsolation(t *testing.T) {
	repository := newCaseRepository()
	repository.incidents["tenant-a/inc-1"] = core.Incident{ID: "inc-1", TenantID: "tenant-a", Severity: core.SeverityMedium}
	service := NewService(repository)
	item, _, err := service.Create(context.Background(), "tenant-a", "analyst", CreateInput{Title: "Tenant scoped", IncidentIDs: []string{"inc-1"}, RequestID: "request"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Case(context.Background(), "tenant-b", item.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("cross-tenant lookup returned %v", err)
	}
	if _, err := service.AddComment(context.Background(), "tenant-a", item.ID, "analyst", "stale", "request-2", item.Version+1); !errors.Is(err, store.ErrVersionConflict) {
		t.Fatalf("stale mutation returned %v", err)
	}
}

type caseRepository struct {
	cases     map[string]core.Case
	requests  map[string]string
	incidents map[string]core.Incident
	evidence  []core.EvidenceItem
	audits    []core.AuditEntry
}

func newCaseRepository() *caseRepository {
	return &caseRepository{cases: map[string]core.Case{}, requests: map[string]string{}, incidents: map[string]core.Incident{}}
}
func caseKey(tenantID, id string) string { return tenantID + "/" + id }
func cloneCase(value core.Case) core.Case {
	payload, _ := json.Marshal(value)
	var result core.Case
	_ = json.Unmarshal(payload, &result)
	result.RequestID = value.RequestID
	return result
}
func (r *caseRepository) CreateCase(_ context.Context, item core.Case) (core.Case, bool, error) {
	requestKey := caseKey(item.TenantID, item.RequestID)
	if id := r.requests[requestKey]; id != "" {
		return cloneCase(r.cases[caseKey(item.TenantID, id)]), true, nil
	}
	r.cases[caseKey(item.TenantID, item.ID)] = cloneCase(item)
	r.requests[requestKey] = item.ID
	return cloneCase(item), false, nil
}
func (r *caseRepository) GetCase(_ context.Context, tenantID, id string) (core.Case, error) {
	value, ok := r.cases[caseKey(tenantID, id)]
	if !ok {
		return core.Case{}, store.ErrNotFound
	}
	return cloneCase(value), nil
}
func (r *caseRepository) ListCases(_ context.Context, tenantID string, _ core.CaseFilter) ([]core.Case, error) {
	values := []core.Case{}
	for _, value := range r.cases {
		if value.TenantID == tenantID {
			values = append(values, cloneCase(value))
		}
	}
	return values, nil
}
func (r *caseRepository) MutateCase(_ context.Context, tenantID, id string, version int, mutate func(*core.Case) error) (core.Case, error) {
	key := caseKey(tenantID, id)
	value, ok := r.cases[key]
	if !ok {
		return core.Case{}, store.ErrNotFound
	}
	if version > 0 && value.Version != version {
		return core.Case{}, store.ErrVersionConflict
	}
	value = cloneCase(value)
	if err := mutate(&value); err != nil {
		return core.Case{}, err
	}
	value.Version++
	value.UpdatedAt = time.Now().UTC()
	r.cases[key] = cloneCase(value)
	return value, nil
}
func (r *caseRepository) GetIncident(_ context.Context, tenantID, id string) (core.Incident, error) {
	value, ok := r.incidents[caseKey(tenantID, id)]
	if !ok {
		return core.Incident{}, store.ErrNotFound
	}
	return value, nil
}
func (r *caseRepository) ListEvidence(_ context.Context, tenantID string, filter core.EvidenceFilter) ([]core.EvidenceItem, error) {
	values := []core.EvidenceItem{}
	for _, value := range r.evidence {
		if value.TenantID == tenantID && (filter.CaseID == "" || value.CaseID == filter.CaseID) {
			values = append(values, value)
		}
	}
	return values, nil
}
func (r *caseRepository) AppendAudit(_ context.Context, value core.AuditEntry) (core.AuditEntry, error) {
	r.audits = append(r.audits, value)
	return value, nil
}
