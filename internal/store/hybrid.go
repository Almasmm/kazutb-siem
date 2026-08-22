package store

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/ingest"
)

type Hybrid struct {
	control   *Postgres
	telemetry *ClickHouse
}

func OpenHybrid(ctx context.Context, databaseURL, clickhouseURL string) (*Hybrid, error) {
	control, err := OpenPostgres(ctx, databaseURL)
	if err != nil {
		return nil, err
	}
	telemetry, err := OpenClickHouse(ctx, clickhouseURL)
	if err != nil {
		control.Close()
		return nil, err
	}
	return &Hybrid{control: control, telemetry: telemetry}, nil
}

func (h *Hybrid) Health(ctx context.Context) error {
	if err := h.control.Health(ctx); err != nil {
		return err
	}
	return h.telemetry.Health(ctx)
}
func (h *Hybrid) Close() { h.telemetry.Close(); h.control.Close() }
func (h *Hybrid) EnsureTenant(ctx context.Context, tenantID, name string) error {
	return h.control.EnsureTenant(ctx, tenantID, name)
}
func (h *Hybrid) RegisterCollector(ctx context.Context, collector core.Collector) (core.Collector, error) {
	return h.control.RegisterCollector(ctx, collector)
}
func (h *Hybrid) ListCollectors(ctx context.Context, tenantID string) ([]core.Collector, error) {
	return h.control.ListCollectors(ctx, tenantID)
}
func (h *Hybrid) CollectorBySubject(ctx context.Context, tenantID, subject string) (core.Collector, error) {
	return h.control.CollectorBySubject(ctx, tenantID, subject)
}
func (h *Hybrid) HeartbeatCollector(ctx context.Context, tenantID, subject string, heartbeat core.CollectorHeartbeat, observedIP string) (core.Collector, error) {
	return h.control.HeartbeatCollector(ctx, tenantID, subject, heartbeat, observedIP)
}
func (h *Hybrid) SetCollectorState(ctx context.Context, tenantID, collectorID, state string) (core.Collector, error) {
	return h.control.SetCollectorState(ctx, tenantID, collectorID, state)
}
func (h *Hybrid) CreateDetectionDraft(ctx context.Context, content core.DetectionContent) (core.DetectionContent, error) {
	return h.control.CreateDetectionDraft(ctx, content)
}
func (h *Hybrid) DetectionContent(ctx context.Context, tenantID, ruleID, version string) (core.DetectionContent, error) {
	return h.control.DetectionContent(ctx, tenantID, ruleID, version)
}
func (h *Hybrid) ListDetectionContent(ctx context.Context, tenantID string) ([]core.DetectionContent, error) {
	return h.control.ListDetectionContent(ctx, tenantID)
}
func (h *Hybrid) SaveDetectionValidation(ctx context.Context, content core.DetectionContent, rule core.DetectionRule, report core.DetectionValidationReport) (core.DetectionContent, error) {
	return h.control.SaveDetectionValidation(ctx, content, rule, report)
}
func (h *Hybrid) PublishDetectionContent(ctx context.Context, tenantID, ruleID, version string) (core.DetectionContent, error) {
	return h.control.PublishDetectionContent(ctx, tenantID, ruleID, version)
}
func (h *Hybrid) DisableDetectionContent(ctx context.Context, tenantID, ruleID string) (core.DetectionContent, error) {
	return h.control.DisableDetectionContent(ctx, tenantID, ruleID)
}
func (h *Hybrid) RollbackDetectionContent(ctx context.Context, tenantID, ruleID string) (core.DetectionContent, error) {
	return h.control.RollbackDetectionContent(ctx, tenantID, ruleID)
}
func (h *Hybrid) PublishedDetectionContent(ctx context.Context, tenantID string) ([]core.DetectionContent, error) {
	return h.control.PublishedDetectionContent(ctx, tenantID)
}
func (h *Hybrid) ObserveCorrelation(ctx context.Context, input core.CorrelationObservation) (core.CorrelationEvaluation, error) {
	return h.control.ObserveCorrelation(ctx, input)
}
func (h *Hybrid) ResetTenant(ctx context.Context, tenantID string) error {
	if err := h.telemetry.ResetTenant(ctx, tenantID); err != nil {
		return err
	}
	return h.control.ResetTenant(ctx, tenantID)
}
func (h *Hybrid) SetRules(ctx context.Context, rules []core.DetectionRule) error {
	return h.control.SetRules(ctx, rules)
}
func (h *Hybrid) ListRules(ctx context.Context) ([]core.DetectionRule, error) {
	return h.control.ListRules(ctx)
}
func (h *Hybrid) PutRawEnvelope(ctx context.Context, envelope ingest.RawEnvelope) error {
	return h.telemetry.PutRawEnvelope(ctx, envelope)
}
func (h *Hybrid) PutEvent(ctx context.Context, event core.CanonicalEvent) (core.CanonicalEvent, bool, error) {
	return h.telemetry.PutEvent(ctx, event)
}
func (h *Hybrid) GetEvent(ctx context.Context, tenantID, eventID string) (core.CanonicalEvent, error) {
	event, err := h.telemetry.GetEvent(ctx, tenantID, eventID)
	if !errors.Is(err, ErrNotFound) {
		return event, err
	}
	return h.control.GetEvent(ctx, tenantID, eventID)
}
func (h *Hybrid) ListEvents(ctx context.Context, tenantID string, filter EventFilter) ([]core.CanonicalEvent, error) {
	current, err := h.telemetry.ListEvents(ctx, tenantID, filter)
	if err != nil {
		return nil, err
	}
	legacy, err := h.control.ListEvents(ctx, tenantID, filter)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	merged := make([]core.CanonicalEvent, 0, len(current)+len(legacy))
	for _, event := range append(current, legacy...) {
		if !seen[event.ID] {
			merged = append(merged, event)
			seen[event.ID] = true
		}
	}
	sort.Slice(merged, func(i, j int) bool { return merged[i].EventTime.After(merged[j].EventTime) })
	limit := normalizedLimit(filter.Limit)
	if len(merged) > limit {
		merged = merged[:limit]
	}
	return merged, nil
}
func (h *Hybrid) PutFinding(ctx context.Context, finding core.Finding) error {
	return h.telemetry.PutFinding(ctx, finding)
}
func (h *Hybrid) ListFindings(ctx context.Context, tenantID, eventID string, limit int) ([]core.Finding, error) {
	current, err := h.telemetry.ListFindings(ctx, tenantID, eventID, limit)
	if err != nil {
		return nil, err
	}
	legacy, err := h.control.ListFindings(ctx, tenantID, eventID, limit)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	merged := make([]core.Finding, 0, len(current)+len(legacy))
	for _, finding := range append(current, legacy...) {
		if !seen[finding.ID] {
			merged = append(merged, finding)
			seen[finding.ID] = true
		}
	}
	sort.Slice(merged, func(i, j int) bool { return merged[i].CreatedAt.After(merged[j].CreatedAt) })
	limit = normalizedLimit(limit)
	if len(merged) > limit {
		merged = merged[:limit]
	}
	return merged, nil
}
func (h *Hybrid) UpsertAlert(ctx context.Context, alert core.Alert, key string, window time.Duration) (core.Alert, bool, error) {
	return h.control.UpsertAlert(ctx, alert, key, window)
}
func (h *Hybrid) GetAlert(ctx context.Context, tenantID, alertID string) (core.Alert, error) {
	return h.control.GetAlert(ctx, tenantID, alertID)
}
func (h *Hybrid) ListAlerts(ctx context.Context, tenantID string, filter AlertFilter) ([]core.Alert, error) {
	return h.control.ListAlerts(ctx, tenantID, filter)
}
func (h *Hybrid) MutateAlert(ctx context.Context, tenantID, alertID string, version int, mutate func(*core.Alert) error) (core.Alert, error) {
	return h.control.MutateAlert(ctx, tenantID, alertID, version, mutate)
}
func (h *Hybrid) CreateIncident(ctx context.Context, incident core.Incident) (core.Incident, error) {
	return h.control.CreateIncident(ctx, incident)
}
func (h *Hybrid) GetIncident(ctx context.Context, tenantID, incidentID string) (core.Incident, error) {
	return h.control.GetIncident(ctx, tenantID, incidentID)
}
func (h *Hybrid) ListIncidents(ctx context.Context, tenantID string, filter IncidentFilter) ([]core.Incident, error) {
	return h.control.ListIncidents(ctx, tenantID, filter)
}
func (h *Hybrid) MutateIncident(ctx context.Context, tenantID, incidentID string, version int, mutate func(*core.Incident) error) (core.Incident, error) {
	return h.control.MutateIncident(ctx, tenantID, incidentID, version, mutate)
}
func (h *Hybrid) AppendAudit(ctx context.Context, entry core.AuditEntry) (core.AuditEntry, error) {
	return h.control.AppendAudit(ctx, entry)
}
func (h *Hybrid) ListAudit(ctx context.Context, tenantID string, limit int) ([]core.AuditEntry, error) {
	return h.control.ListAudit(ctx, tenantID, limit)
}
func (h *Hybrid) VerifyAudit(ctx context.Context, tenantID string) (bool, error) {
	return h.control.VerifyAudit(ctx, tenantID)
}
func (h *Hybrid) Overview(ctx context.Context, tenantID string) (map[string]interface{}, error) {
	overview, err := h.control.Overview(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	telemetry, err := h.telemetry.Metrics(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	metrics := overview["metrics"].(map[string]interface{})
	legacyEvents, _ := metrics["events_24h"].(int)
	metrics["events_24h"] = legacyEvents + telemetry.Events24h
	metrics["detection_latency_ms"] = telemetry.DetectionLatencyMS
	platform := overview["platform"].(map[string]interface{})
	platform["profile"] = "kafka-clickhouse-postgres"
	return overview, nil
}
