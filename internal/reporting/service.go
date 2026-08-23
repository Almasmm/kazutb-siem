package reporting

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/mitre"
	"github.com/kcsp/platform/internal/store"
)

var ErrInvalidReport = errors.New("invalid report request")

type Repository interface {
	CreateReportRun(context.Context, core.ReportRun) (core.ReportRun, bool, error)
	GetReportRun(context.Context, string, string) (core.ReportRun, error)
	ListReportRuns(context.Context, string, core.ReportFilter) ([]core.ReportRun, error)
	Overview(context.Context, string) (map[string]interface{}, error)
	ListAlerts(context.Context, string, store.AlertFilter) ([]core.Alert, error)
	ListIncidents(context.Context, string, store.IncidentFilter) ([]core.Incident, error)
	GetIncident(context.Context, string, string) (core.Incident, error)
	ListAudit(context.Context, string, int) ([]core.AuditEntry, error)
	ListRules(context.Context) ([]core.DetectionRule, error)
	PublishedDetectionContent(context.Context, string) ([]core.DetectionContent, error)
	ListCollectors(context.Context, string) ([]core.Collector, error)
	ListEntities(context.Context, string, core.EntityFilter) ([]core.SecurityEntity, error)
	GetEvent(context.Context, string, string) (core.CanonicalEvent, error)
	ListFindings(context.Context, string, string, int) ([]core.Finding, error)
	GetCase(context.Context, string, string) (core.Case, error)
	ListCases(context.Context, string, core.CaseFilter) ([]core.Case, error)
	ListEvidence(context.Context, string, core.EvidenceFilter) ([]core.EvidenceItem, error)
}

type Service struct{ repository Repository }

type GenerateInput struct {
	Type       string                `json:"report_type"`
	Parameters core.ReportParameters `json:"parameters"`
	RequestID  string                `json:"request_id,omitempty"`
}

func NewService(repository Repository) *Service { return &Service{repository: repository} }

func (s *Service) Reports(ctx context.Context, tenantID string, filter core.ReportFilter) ([]core.ReportRun, error) {
	return s.repository.ListReportRuns(ctx, tenantID, filter)
}

func (s *Service) Report(ctx context.Context, tenantID, reportID string) (core.ReportRun, error) {
	return s.repository.GetReportRun(ctx, tenantID, strings.TrimSpace(reportID))
}

func (s *Service) Generate(ctx context.Context, tenantID, actor string, input GenerateInput) (core.ReportRun, bool, error) {
	input.Type = strings.ToUpper(strings.TrimSpace(input.Type))
	parameters, err := normalizeParameters(input.Type, input.Parameters, time.Now().UTC())
	if err != nil {
		return core.ReportRun{}, false, err
	}
	snapshot, title, err := s.snapshot(ctx, tenantID, input.Type, parameters)
	if err != nil {
		return core.ReportRun{}, false, err
	}
	payload, err := json.Marshal(snapshot)
	if err != nil {
		return core.ReportRun{}, false, fmt.Errorf("encode report snapshot: %w", err)
	}
	sum := sha256.Sum256(payload)
	now := time.Now().UTC()
	run := core.ReportRun{
		ID: core.NewID("rpt"), TenantID: tenantID, Type: input.Type, Title: title, Status: "COMPLETED",
		Parameters: parameters, Snapshot: snapshot, Checksum: "sha256:" + hex.EncodeToString(sum[:]),
		CreatedBy: actor, RequestID: strings.TrimSpace(input.RequestID), CreatedAt: now, CompletedAt: &now,
	}
	return s.repository.CreateReportRun(ctx, run)
}

func (s *Service) Render(run core.ReportRun, format string) ([]byte, string, string, error) {
	format = strings.ToLower(strings.TrimSpace(format))
	switch format {
	case "", "json":
		payload, err := json.MarshalIndent(run, "", "  ")
		return payload, "application/json", safeFilename(run) + ".json", err
	case "csv":
		payload, err := renderCSV(run)
		return payload, "text/csv; charset=utf-8", safeFilename(run) + ".csv", err
	case "html":
		payload, err := json.MarshalIndent(run.Snapshot, "", "  ")
		if err != nil {
			return nil, "", "", err
		}
		body := "<!doctype html><html><head><meta charset=\"utf-8\"><title>" + html.EscapeString(run.Title) + "</title><style>body{font:14px/1.5 sans-serif;margin:40px;color:#17212b}h1{margin-bottom:4px}small{color:#667}pre{white-space:pre-wrap;background:#f4f6f8;padding:18px;border-radius:8px}</style></head><body><h1>" + html.EscapeString(run.Title) + "</h1><small>" + html.EscapeString(run.ID+" · "+run.Checksum) + "</small><pre>" + html.EscapeString(string(payload)) + "</pre></body></html>"
		return []byte(body), "text/html; charset=utf-8", safeFilename(run) + ".html", nil
	default:
		return nil, "", "", fmt.Errorf("%w: format must be json, csv or html", ErrInvalidReport)
	}
}

func (s *Service) snapshot(ctx context.Context, tenantID, reportType string, parameters core.ReportParameters) (map[string]interface{}, string, error) {
	switch reportType {
	case core.ReportTypeExecutive, core.ReportTypeSOC:
		return s.operationalSnapshot(ctx, tenantID, reportType, parameters)
	case core.ReportTypeIncident:
		return s.incidentSnapshot(ctx, tenantID, parameters)
	case core.ReportTypeCase:
		return s.caseSnapshot(ctx, tenantID, parameters)
	default:
		return nil, "", fmt.Errorf("%w: unsupported report type %q", ErrInvalidReport, reportType)
	}
}

func (s *Service) operationalSnapshot(ctx context.Context, tenantID, reportType string, parameters core.ReportParameters) (map[string]interface{}, string, error) {
	overview, err := s.repository.Overview(ctx, tenantID)
	if err != nil {
		return nil, "", err
	}
	alerts, err := s.repository.ListAlerts(ctx, tenantID, store.AlertFilter{Limit: 1000})
	if err != nil {
		return nil, "", err
	}
	incidents, err := s.repository.ListIncidents(ctx, tenantID, store.IncidentFilter{Limit: 1000})
	if err != nil {
		return nil, "", err
	}
	collectors, err := s.repository.ListCollectors(ctx, tenantID)
	if err != nil {
		return nil, "", err
	}
	entities, err := s.repository.ListEntities(ctx, tenantID, core.EntityFilter{Limit: 100})
	if err != nil {
		return nil, "", err
	}
	alerts = filterAlerts(alerts, parameters.Start, parameters.End)
	incidents = filterIncidents(incidents, parameters.Start, parameters.End)
	coverage, err := mitre.NewService(s.repository).Coverage(ctx, tenantID)
	if err != nil {
		return nil, "", err
	}
	metrics, breakdowns, topDetections, topEntities := operationalMetrics(alerts, incidents, collectors, entities, overview)
	title := "Executive security report"
	if reportType == core.ReportTypeSOC {
		title = "SOC operations report"
	}
	return map[string]interface{}{
		"period":  map[string]interface{}{"start": parameters.Start, "end": parameters.End, "timezone": "Asia/Qyzylorda"},
		"metrics": metrics, "breakdowns": breakdowns, "top_detections": topDetections, "top_entities": topEntities,
		"mitre_coverage": coverage, "collector_health": collectors, "overview": overview,
	}, title, nil
}

func (s *Service) incidentSnapshot(ctx context.Context, tenantID string, parameters core.ReportParameters) (map[string]interface{}, string, error) {
	incident, err := s.repository.GetIncident(ctx, tenantID, parameters.IncidentID)
	if err != nil {
		return nil, "", err
	}
	events := []core.CanonicalEvent{}
	findings := []core.Finding{}
	for _, eventID := range incident.EventIDs {
		if len(events) >= 200 {
			break
		}
		event, eventErr := s.repository.GetEvent(ctx, tenantID, eventID)
		if eventErr == nil {
			events = append(events, event)
		}
		items, findingErr := s.repository.ListFindings(ctx, tenantID, eventID, 100)
		if findingErr == nil {
			findings = append(findings, items...)
		}
	}
	evidence, err := s.repository.ListEvidence(ctx, tenantID, core.EvidenceFilter{IncidentID: incident.ID, Limit: 500})
	if err != nil {
		return nil, "", err
	}
	cases, err := s.repository.ListCases(ctx, tenantID, core.CaseFilter{IncidentID: incident.ID, Limit: 100})
	if err != nil {
		return nil, "", err
	}
	return map[string]interface{}{"incident": incident, "events": events, "findings": findings, "evidence": evidence, "cases": cases, "evidence_bytes_embedded": false}, "Incident report · " + incident.ID, nil
}

func (s *Service) caseSnapshot(ctx context.Context, tenantID string, parameters core.ReportParameters) (map[string]interface{}, string, error) {
	caseItem, err := s.repository.GetCase(ctx, tenantID, parameters.CaseID)
	if err != nil {
		return nil, "", err
	}
	evidence, err := s.repository.ListEvidence(ctx, tenantID, core.EvidenceFilter{CaseID: caseItem.ID, Limit: 500})
	if err != nil {
		return nil, "", err
	}
	incidents := []core.Incident{}
	for _, incidentID := range caseItem.IncidentIDs {
		incident, incidentErr := s.repository.GetIncident(ctx, tenantID, incidentID)
		if incidentErr == nil {
			incidents = append(incidents, incident)
		}
	}
	return map[string]interface{}{"case": caseItem, "incidents": incidents, "evidence": evidence, "evidence_bytes_embedded": false}, "Case closure report · " + caseItem.ID, nil
}

func operationalMetrics(alerts []core.Alert, incidents []core.Incident, collectors []core.Collector, entities []core.SecurityEntity, overview map[string]interface{}) ([]core.ReportMetric, map[string][]core.ReportBucket, []core.ReportBucket, []core.ReportBucket) {
	alertStatus, alertSeverity, incidentStatus := map[string]int{}, map[string]int{}, map[string]int{}
	detectionCounts, entityCounts := map[string]int{}, map[string]int{}
	falsePositives, breached := 0, 0
	mttd, mtta, mttr := []time.Duration{}, []time.Duration{}, []time.Duration{}
	for _, alert := range alerts {
		alertStatus[alert.Status]++
		alertSeverity[string(alert.Severity)]++
		detectionCounts[firstValue(alert.Rule.ID, "unmapped")]++
		entityCounts[firstValue(alert.Entity.Name, alert.Entity.ID, "unknown")]++
		if strings.Contains(strings.ToUpper(alert.Disposition), "FALSE") {
			falsePositives++
		}
		if alert.SLA.Breached {
			breached++
		}
		if !alert.FirstSeen.IsZero() && alert.CreatedAt.After(alert.FirstSeen) {
			mttd = append(mttd, alert.CreatedAt.Sub(alert.FirstSeen))
		}
		if alert.SLA.Acknowledged != nil && alert.SLA.Acknowledged.After(alert.CreatedAt) {
			mtta = append(mtta, alert.SLA.Acknowledged.Sub(alert.CreatedAt))
		}
	}
	for _, incident := range incidents {
		incidentStatus[incident.Status]++
		if strings.EqualFold(incident.Status, "CLOSED") && incident.UpdatedAt.After(incident.CreatedAt) {
			mttr = append(mttr, incident.UpdatedAt.Sub(incident.CreatedAt))
		}
	}
	healthyCollectors := 0
	for _, collector := range collectors {
		if strings.EqualFold(collector.Health, "HEALTHY") || strings.EqualFold(collector.State, "ACTIVE") {
			healthyCollectors++
		}
	}
	events24h := numericValue(overview["events_24h"])
	metrics := []core.ReportMetric{
		{Key: "alerts", Value: float64(len(alerts)), Unit: "count"}, {Key: "incidents", Value: float64(len(incidents)), Unit: "count"},
		{Key: "mttd_minutes", Value: averageMinutes(mttd), Unit: "minutes"}, {Key: "mtta_minutes", Value: averageMinutes(mtta), Unit: "minutes"}, {Key: "mttr_minutes", Value: averageMinutes(mttr), Unit: "minutes"},
		{Key: "sla_breaches", Value: float64(breached), Unit: "count"}, {Key: "false_positive_rate", Value: percentage(falsePositives, len(alerts)), Unit: "percent"},
		{Key: "active_collectors", Value: float64(len(collectors)), Unit: "count"}, {Key: "healthy_collectors", Value: float64(healthyCollectors), Unit: "count"},
		{Key: "events_24h", Value: events24h, Unit: "events"}, {Key: "average_eps_24h", Value: events24h / 86400, Unit: "events_per_second"},
		{Key: "known_entities", Value: float64(len(entities)), Unit: "count"},
	}
	return metrics, map[string][]core.ReportBucket{"alert_status": buckets(alertStatus), "alert_severity": buckets(alertSeverity), "incident_status": buckets(incidentStatus)}, topBuckets(detectionCounts, 10), topBuckets(entityCounts, 10)
}

func normalizeParameters(reportType string, parameters core.ReportParameters, now time.Time) (core.ReportParameters, error) {
	parameters.IncidentID, parameters.CaseID = strings.TrimSpace(parameters.IncidentID), strings.TrimSpace(parameters.CaseID)
	switch reportType {
	case core.ReportTypeExecutive, core.ReportTypeSOC:
		if parameters.End.IsZero() {
			parameters.End = now
		}
		if parameters.Start.IsZero() {
			parameters.Start = parameters.End.Add(-30 * 24 * time.Hour)
		}
		parameters.Start, parameters.End = parameters.Start.UTC(), parameters.End.UTC()
		if !parameters.Start.Before(parameters.End) || parameters.End.Sub(parameters.Start) > 366*24*time.Hour {
			return core.ReportParameters{}, fmt.Errorf("%w: period must be positive and no longer than 366 days", ErrInvalidReport)
		}
	case core.ReportTypeIncident:
		if parameters.IncidentID == "" {
			return core.ReportParameters{}, fmt.Errorf("%w: incident_id is required", ErrInvalidReport)
		}
	case core.ReportTypeCase:
		if parameters.CaseID == "" {
			return core.ReportParameters{}, fmt.Errorf("%w: case_id is required", ErrInvalidReport)
		}
	default:
		return core.ReportParameters{}, fmt.Errorf("%w: unsupported report type", ErrInvalidReport)
	}
	return parameters, nil
}

func renderCSV(run core.ReportRun) ([]byte, error) {
	var buffer bytes.Buffer
	buffer.Write([]byte{0xef, 0xbb, 0xbf})
	writer := csv.NewWriter(&buffer)
	_ = writer.Write([]string{"section", "key", "value"})
	_ = writer.Write([]string{"report", "report_id", run.ID})
	_ = writer.Write([]string{"report", "type", run.Type})
	_ = writer.Write([]string{"report", "checksum_sha256", run.Checksum})
	keys := make([]string, 0, len(run.Snapshot))
	for key := range run.Snapshot {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		value, _ := json.Marshal(run.Snapshot[key])
		_ = writer.Write([]string{"snapshot", key, string(value)})
	}
	writer.Flush()
	return buffer.Bytes(), writer.Error()
}

func filterAlerts(items []core.Alert, start, end time.Time) []core.Alert {
	result := []core.Alert{}
	for _, item := range items {
		if !item.CreatedAt.Before(start) && item.CreatedAt.Before(end) {
			result = append(result, item)
		}
	}
	return result
}

func filterIncidents(items []core.Incident, start, end time.Time) []core.Incident {
	result := []core.Incident{}
	for _, item := range items {
		if !item.CreatedAt.Before(start) && item.CreatedAt.Before(end) {
			result = append(result, item)
		}
	}
	return result
}

func buckets(values map[string]int) []core.ReportBucket {
	items := make([]core.ReportBucket, 0, len(values))
	for key, count := range values {
		items = append(items, core.ReportBucket{Key: key, Label: key, Count: count})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Key < items[j].Key })
	return items
}

func topBuckets(values map[string]int, limit int) []core.ReportBucket {
	items := buckets(values)
	sort.Slice(items, func(i, j int) bool {
		if items[i].Count != items[j].Count {
			return items[i].Count > items[j].Count
		}
		return items[i].Key < items[j].Key
	})
	if len(items) > limit {
		items = items[:limit]
	}
	return items
}

func averageMinutes(values []time.Duration) float64 {
	if len(values) == 0 {
		return 0
	}
	var total time.Duration
	for _, value := range values {
		total += value
	}
	return (total / time.Duration(len(values))).Minutes()
}

func percentage(part, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(part) * 100 / float64(total)
}

func numericValue(value interface{}) float64 {
	switch typed := value.(type) {
	case int:
		return float64(typed)
	case int64:
		return float64(typed)
	case float64:
		return typed
	case json.Number:
		result, _ := typed.Float64()
		return result
	case string:
		result, _ := strconv.ParseFloat(typed, 64)
		return result
	default:
		return 0
	}
}

func firstValue(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}

func safeFilename(run core.ReportRun) string {
	return strings.ToLower(strings.ReplaceAll(run.Type, "_", "-")) + "-" + run.ID
}
