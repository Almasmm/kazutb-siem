package store

import (
	"context"
	"sync"
	"time"

	"github.com/kcsp/platform/internal/core"
)

// Repository is the durable boundary shared by the data and control planes.
// Every operation accepts a context and returns storage failures to its caller;
// production adapters must never silently fall back to process memory.
type Repository interface {
	Health(context.Context) error
	Close()
	EnsureTenant(context.Context, string, string) error
	ResetTenant(context.Context, string) error

	SetRules(context.Context, []core.DetectionRule) error
	ListRules(context.Context) ([]core.DetectionRule, error)

	PutEvent(context.Context, core.CanonicalEvent) (core.CanonicalEvent, bool, error)
	GetEvent(context.Context, string, string) (core.CanonicalEvent, error)
	ListEvents(context.Context, string, EventFilter) ([]core.CanonicalEvent, error)
	ObserveEntityEvent(context.Context, core.CanonicalEvent) error
	ListEntities(context.Context, string, core.EntityFilter) ([]core.SecurityEntity, error)
	GetEntity(context.Context, string, string) (core.SecurityEntity, error)
	GetEntityGraph(context.Context, string, string, int, int) (core.EntityGraph, error)
	PutFinding(context.Context, core.Finding) error
	ListFindings(context.Context, string, string, int) ([]core.Finding, error)

	UpsertAlert(context.Context, core.Alert, string, time.Duration) (core.Alert, bool, error)
	GetAlert(context.Context, string, string) (core.Alert, error)
	ListAlerts(context.Context, string, AlertFilter) ([]core.Alert, error)
	MutateAlert(context.Context, string, string, int, func(*core.Alert) error) (core.Alert, error)

	CreateIncident(context.Context, core.Incident) (core.Incident, error)
	GetIncident(context.Context, string, string) (core.Incident, error)
	ListIncidents(context.Context, string, IncidentFilter) ([]core.Incident, error)
	MutateIncident(context.Context, string, string, int, func(*core.Incident) error) (core.Incident, error)

	AppendAudit(context.Context, core.AuditEntry) (core.AuditEntry, error)
	ListAudit(context.Context, string, int) ([]core.AuditEntry, error)
	VerifyAudit(context.Context, string) (bool, error)
	Overview(context.Context, string) (map[string]interface{}, error)
}

// MemoryRepository adapts the original deterministic in-memory implementation
// to Repository. It is intentionally retained for unit tests and explicit demo
// tooling, never as an automatic production fallback.
type MemoryRepository struct {
	memory                 *Memory
	entityMu               sync.RWMutex
	entities               map[string]map[string]core.SecurityEntity
	entityRelations        map[string]map[string]core.EntityRelation
	seenEntityObservations map[string]struct{}
	seenRelationEvents     map[string]struct{}
}

func WrapMemory(memory *Memory) *MemoryRepository {
	return &MemoryRepository{
		memory: memory, entities: map[string]map[string]core.SecurityEntity{}, entityRelations: map[string]map[string]core.EntityRelation{},
		seenEntityObservations: map[string]struct{}{}, seenRelationEvents: map[string]struct{}{},
	}
}

func NewMemoryRepository() *MemoryRepository {
	return WrapMemory(NewMemory())
}

func (m *MemoryRepository) Memory() *Memory { return m.memory }

func (m *MemoryRepository) Health(ctx context.Context) error { return ctx.Err() }
func (m *MemoryRepository) Close()                           {}
func (m *MemoryRepository) EnsureTenant(ctx context.Context, _, _ string) error {
	return ctx.Err()
}
func (m *MemoryRepository) ResetTenant(ctx context.Context, tenantID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.memory.ResetTenant(tenantID)
	m.resetEntities(tenantID)
	return nil
}
func (m *MemoryRepository) SetRules(ctx context.Context, rules []core.DetectionRule) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.memory.SetRules(rules)
	return nil
}
func (m *MemoryRepository) ListRules(ctx context.Context) ([]core.DetectionRule, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return m.memory.ListRules(), nil
}
func (m *MemoryRepository) PutEvent(ctx context.Context, event core.CanonicalEvent) (core.CanonicalEvent, bool, error) {
	if err := ctx.Err(); err != nil {
		return core.CanonicalEvent{}, false, err
	}
	stored, duplicate := m.memory.PutEvent(event)
	return stored, duplicate, nil
}
func (m *MemoryRepository) GetEvent(ctx context.Context, tenantID, eventID string) (core.CanonicalEvent, error) {
	if err := ctx.Err(); err != nil {
		return core.CanonicalEvent{}, err
	}
	return m.memory.GetEvent(tenantID, eventID)
}
func (m *MemoryRepository) ListEvents(ctx context.Context, tenantID string, filter EventFilter) ([]core.CanonicalEvent, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return m.memory.ListEvents(tenantID, filter), nil
}
func (m *MemoryRepository) PutFinding(ctx context.Context, finding core.Finding) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.memory.PutFinding(finding)
	return nil
}
func (m *MemoryRepository) ListFindings(ctx context.Context, tenantID, eventID string, limit int) ([]core.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return m.memory.ListFindings(tenantID, eventID, limit), nil
}
func (m *MemoryRepository) UpsertAlert(ctx context.Context, candidate core.Alert, dedupKey string, window time.Duration) (core.Alert, bool, error) {
	if err := ctx.Err(); err != nil {
		return core.Alert{}, false, err
	}
	alert, created := m.memory.UpsertAlert(candidate, dedupKey, window)
	return alert, created, nil
}
func (m *MemoryRepository) GetAlert(ctx context.Context, tenantID, alertID string) (core.Alert, error) {
	if err := ctx.Err(); err != nil {
		return core.Alert{}, err
	}
	return m.memory.GetAlert(tenantID, alertID)
}
func (m *MemoryRepository) ListAlerts(ctx context.Context, tenantID string, filter AlertFilter) ([]core.Alert, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return m.memory.ListAlerts(tenantID, filter), nil
}
func (m *MemoryRepository) MutateAlert(ctx context.Context, tenantID, alertID string, expectedVersion int, mutate func(*core.Alert) error) (core.Alert, error) {
	if err := ctx.Err(); err != nil {
		return core.Alert{}, err
	}
	return m.memory.MutateAlert(tenantID, alertID, expectedVersion, mutate)
}
func (m *MemoryRepository) CreateIncident(ctx context.Context, incident core.Incident) (core.Incident, error) {
	if err := ctx.Err(); err != nil {
		return core.Incident{}, err
	}
	return m.memory.CreateIncident(incident)
}
func (m *MemoryRepository) GetIncident(ctx context.Context, tenantID, incidentID string) (core.Incident, error) {
	if err := ctx.Err(); err != nil {
		return core.Incident{}, err
	}
	return m.memory.GetIncident(tenantID, incidentID)
}
func (m *MemoryRepository) ListIncidents(ctx context.Context, tenantID string, filter IncidentFilter) ([]core.Incident, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return m.memory.ListIncidents(tenantID, filter), nil
}
func (m *MemoryRepository) MutateIncident(ctx context.Context, tenantID, incidentID string, expectedVersion int, mutate func(*core.Incident) error) (core.Incident, error) {
	if err := ctx.Err(); err != nil {
		return core.Incident{}, err
	}
	return m.memory.MutateIncident(tenantID, incidentID, expectedVersion, mutate)
}
func (m *MemoryRepository) AppendAudit(ctx context.Context, entry core.AuditEntry) (core.AuditEntry, error) {
	if err := ctx.Err(); err != nil {
		return core.AuditEntry{}, err
	}
	return m.memory.AppendAudit(entry), nil
}
func (m *MemoryRepository) ListAudit(ctx context.Context, tenantID string, limit int) ([]core.AuditEntry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return m.memory.ListAudit(tenantID, limit), nil
}
func (m *MemoryRepository) VerifyAudit(ctx context.Context, tenantID string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	return m.memory.VerifyAudit(tenantID), nil
}
func (m *MemoryRepository) Overview(ctx context.Context, tenantID string) (map[string]interface{}, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return m.memory.Overview(tenantID), nil
}
