package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/kcsp/platform/internal/core"
)

var (
	ErrNotFound        = errors.New("resource not found")
	ErrVersionConflict = errors.New("resource version conflict")
)

type EventFilter struct {
	Query    string
	Category string
	Severity int
	Limit    int
}

type AlertFilter struct {
	Status   string
	Severity core.Severity
	Assignee string
	Query    string
	Limit    int
}

type IncidentFilter struct {
	Status   string
	Severity core.Severity
	Query    string
	Limit    int
}

type Memory struct {
	mu sync.RWMutex

	events        map[string]map[string]core.CanonicalEvent
	eventOrder    map[string][]string
	findings      map[string]map[string]core.Finding
	findingOrder  map[string][]string
	alerts        map[string]map[string]core.Alert
	alertOrder    map[string][]string
	dedup         map[string]string
	incidents     map[string]map[string]core.Incident
	incidentOrder map[string][]string
	audit         map[string][]core.AuditEntry
	auditHeads    map[string]string
	rules         []core.DetectionRule
}

func NewMemory() *Memory {
	return &Memory{
		events:        map[string]map[string]core.CanonicalEvent{},
		eventOrder:    map[string][]string{},
		findings:      map[string]map[string]core.Finding{},
		findingOrder:  map[string][]string{},
		alerts:        map[string]map[string]core.Alert{},
		alertOrder:    map[string][]string{},
		dedup:         map[string]string{},
		incidents:     map[string]map[string]core.Incident{},
		incidentOrder: map[string][]string{},
		audit:         map[string][]core.AuditEntry{},
		auditHeads:    map[string]string{},
	}
}

func (m *Memory) SetRules(rules []core.DetectionRule) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rules = append([]core.DetectionRule(nil), rules...)
}

func (m *Memory) ListRules() []core.DetectionRule {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := append([]core.DetectionRule(nil), m.rules...)
	sort.Slice(result, func(i, j int) bool { return result[i].UpdatedAt.After(result[j].UpdatedAt) })
	return result
}

func (m *Memory) ensureTenantLocked(tenantID string) {
	if m.events[tenantID] == nil {
		m.events[tenantID] = map[string]core.CanonicalEvent{}
		m.findings[tenantID] = map[string]core.Finding{}
		m.alerts[tenantID] = map[string]core.Alert{}
		m.incidents[tenantID] = map[string]core.Incident{}
	}
}

func (m *Memory) ResetTenant(tenantID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events[tenantID] = map[string]core.CanonicalEvent{}
	m.eventOrder[tenantID] = nil
	m.findings[tenantID] = map[string]core.Finding{}
	m.findingOrder[tenantID] = nil
	m.alerts[tenantID] = map[string]core.Alert{}
	m.alertOrder[tenantID] = nil
	m.incidents[tenantID] = map[string]core.Incident{}
	m.incidentOrder[tenantID] = nil
	m.audit[tenantID] = nil
	m.auditHeads[tenantID] = ""
	for key := range m.dedup {
		if strings.HasPrefix(key, tenantID+"|") {
			delete(m.dedup, key)
		}
	}
}

func (m *Memory) PutEvent(event core.CanonicalEvent) (core.CanonicalEvent, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensureTenantLocked(event.TenantID)
	if existing, ok := m.events[event.TenantID][event.ID]; ok {
		return existing, true
	}
	m.events[event.TenantID][event.ID] = event
	m.eventOrder[event.TenantID] = append(m.eventOrder[event.TenantID], event.ID)
	return event, false
}

func (m *Memory) GetEvent(tenantID, eventID string) (core.CanonicalEvent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	event, ok := m.events[tenantID][eventID]
	if !ok {
		return core.CanonicalEvent{}, ErrNotFound
	}
	return event, nil
}

func (m *Memory) ListEvents(tenantID string, filter EventFilter) []core.CanonicalEvent {
	m.mu.RLock()
	defer m.mu.RUnlock()
	limit := normalizedLimit(filter.Limit)
	query := strings.ToLower(strings.TrimSpace(filter.Query))
	result := make([]core.CanonicalEvent, 0, min(limit, len(m.eventOrder[tenantID])))
	order := m.eventOrder[tenantID]
	for i := len(order) - 1; i >= 0 && len(result) < limit; i-- {
		event := m.events[tenantID][order[i]]
		if filter.Category != "" && !strings.EqualFold(event.Category, filter.Category) {
			continue
		}
		if filter.Severity > 0 && event.Severity != filter.Severity {
			continue
		}
		if query != "" && !eventContains(event, query) {
			continue
		}
		result = append(result, event)
	}
	return result
}

func eventContains(event core.CanonicalEvent, query string) bool {
	searchable := strings.Join([]string{
		event.ID, event.Category, event.ActivityName, event.Source.Vendor, event.Source.Product,
		event.User.Name, event.Device.Hostname, event.Device.IP, event.SrcEndpoint.IP,
		event.DstEndpoint.IP, event.Process.Name, event.Process.CommandLine,
		event.SecurityResult.Outcome, event.Raw.Message,
	}, " ")
	return strings.Contains(strings.ToLower(searchable), query)
}

func (m *Memory) PutFinding(finding core.Finding) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensureTenantLocked(finding.TenantID)
	if _, exists := m.findings[finding.TenantID][finding.ID]; exists {
		return
	}
	m.findings[finding.TenantID][finding.ID] = finding
	m.findingOrder[finding.TenantID] = append(m.findingOrder[finding.TenantID], finding.ID)
}

func (m *Memory) ListFindings(tenantID, eventID string, limit int) []core.Finding {
	m.mu.RLock()
	defer m.mu.RUnlock()
	limit = normalizedLimit(limit)
	result := make([]core.Finding, 0, min(limit, len(m.findingOrder[tenantID])))
	order := m.findingOrder[tenantID]
	for i := len(order) - 1; i >= 0 && len(result) < limit; i-- {
		finding := m.findings[tenantID][order[i]]
		if eventID != "" && finding.EventID != eventID {
			continue
		}
		result = append(result, finding)
	}
	return result
}

func (m *Memory) UpsertAlert(candidate core.Alert, dedupKey string, window time.Duration) (core.Alert, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensureTenantLocked(candidate.TenantID)
	key := candidate.TenantID + "|" + dedupKey
	if existingID := m.dedup[key]; existingID != "" {
		existing, ok := m.alerts[candidate.TenantID][existingID]
		if ok && existing.Status != "CLOSED" && candidate.LastSeen.Sub(existing.LastSeen) <= window {
			existing.FindingIDs = appendUnique(existing.FindingIDs, candidate.FindingIDs...)
			existing.EventIDs = appendUnique(existing.EventIDs, candidate.EventIDs...)
			existing.EventCount = len(existing.EventIDs)
			existing.LastSeen = candidate.LastSeen
			existing.UpdatedAt = candidate.UpdatedAt
			existing.Version++
			if candidate.RiskScore > existing.RiskScore {
				existing.RiskScore = candidate.RiskScore
				existing.RiskBreakdown = candidate.RiskBreakdown
				existing.Severity = candidate.Severity
			}
			m.alerts[candidate.TenantID][existingID] = existing
			return existing, false
		}
	}
	m.alerts[candidate.TenantID][candidate.ID] = candidate
	m.alertOrder[candidate.TenantID] = append(m.alertOrder[candidate.TenantID], candidate.ID)
	m.dedup[key] = candidate.ID
	return candidate, true
}

func (m *Memory) GetAlert(tenantID, alertID string) (core.Alert, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	alert, ok := m.alerts[tenantID][alertID]
	if !ok {
		return core.Alert{}, ErrNotFound
	}
	return alert, nil
}

func (m *Memory) ListAlerts(tenantID string, filter AlertFilter) []core.Alert {
	m.mu.RLock()
	defer m.mu.RUnlock()
	limit := normalizedLimit(filter.Limit)
	query := strings.ToLower(strings.TrimSpace(filter.Query))
	result := make([]core.Alert, 0, min(limit, len(m.alertOrder[tenantID])))
	order := m.alertOrder[tenantID]
	for i := len(order) - 1; i >= 0 && len(result) < limit; i-- {
		alert := m.alerts[tenantID][order[i]]
		if filter.Status != "" && !strings.EqualFold(alert.Status, filter.Status) {
			continue
		}
		if filter.Severity != "" && alert.Severity != filter.Severity {
			continue
		}
		if filter.Assignee != "" && !strings.EqualFold(alert.Assignee, filter.Assignee) {
			continue
		}
		if query != "" {
			value := strings.ToLower(alert.Title + " " + alert.Rule.Title + " " + alert.Entity.Name + " " + alert.Assignee)
			if !strings.Contains(value, query) {
				continue
			}
		}
		result = append(result, alert)
	}
	return result
}

func (m *Memory) MutateAlert(tenantID, alertID string, expectedVersion int, mutate func(*core.Alert) error) (core.Alert, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	alert, ok := m.alerts[tenantID][alertID]
	if !ok {
		return core.Alert{}, ErrNotFound
	}
	if expectedVersion > 0 && alert.Version != expectedVersion {
		return core.Alert{}, ErrVersionConflict
	}
	if err := mutate(&alert); err != nil {
		return core.Alert{}, err
	}
	alert.Version++
	alert.UpdatedAt = time.Now().UTC()
	m.alerts[tenantID][alertID] = alert
	return alert, nil
}

func (m *Memory) CreateIncident(incident core.Incident) (core.Incident, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensureTenantLocked(incident.TenantID)
	if _, exists := m.incidents[incident.TenantID][incident.ID]; exists {
		return core.Incident{}, ErrVersionConflict
	}
	m.incidents[incident.TenantID][incident.ID] = incident
	m.incidentOrder[incident.TenantID] = append(m.incidentOrder[incident.TenantID], incident.ID)
	return incident, nil
}

func (m *Memory) GetIncident(tenantID, incidentID string) (core.Incident, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	incident, ok := m.incidents[tenantID][incidentID]
	if !ok {
		return core.Incident{}, ErrNotFound
	}
	return incident, nil
}

func (m *Memory) ListIncidents(tenantID string, filter IncidentFilter) []core.Incident {
	m.mu.RLock()
	defer m.mu.RUnlock()
	limit := normalizedLimit(filter.Limit)
	query := strings.ToLower(strings.TrimSpace(filter.Query))
	result := make([]core.Incident, 0, min(limit, len(m.incidentOrder[tenantID])))
	order := m.incidentOrder[tenantID]
	for i := len(order) - 1; i >= 0 && len(result) < limit; i-- {
		incident := m.incidents[tenantID][order[i]]
		if filter.Status != "" && !strings.EqualFold(incident.Status, filter.Status) {
			continue
		}
		if filter.Severity != "" && incident.Severity != filter.Severity {
			continue
		}
		if query != "" && !strings.Contains(strings.ToLower(incident.Title+" "+incident.Summary+" "+incident.Assignee), query) {
			continue
		}
		result = append(result, incident)
	}
	return result
}

func (m *Memory) MutateIncident(tenantID, incidentID string, expectedVersion int, mutate func(*core.Incident) error) (core.Incident, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	incident, ok := m.incidents[tenantID][incidentID]
	if !ok {
		return core.Incident{}, ErrNotFound
	}
	if expectedVersion > 0 && incident.Version != expectedVersion {
		return core.Incident{}, ErrVersionConflict
	}
	if err := mutate(&incident); err != nil {
		return core.Incident{}, err
	}
	incident.Version++
	incident.UpdatedAt = time.Now().UTC()
	m.incidents[tenantID][incidentID] = incident
	return incident, nil
}

func (m *Memory) AppendAudit(entry core.AuditEntry) core.AuditEntry {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.appendAuditLocked(entry)
}

func (m *Memory) appendAuditLocked(entry core.AuditEntry) core.AuditEntry {
	if entry.ID == "" {
		entry.ID = core.NewID("aud")
	}
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = time.Now().UTC()
	}
	entry.PreviousHash = m.auditHeads[entry.TenantID]
	entry.Hash = auditHash(entry)
	m.audit[entry.TenantID] = append(m.audit[entry.TenantID], entry)
	m.auditHeads[entry.TenantID] = entry.Hash
	return entry
}

func (m *Memory) ListAudit(tenantID string, limit int) []core.AuditEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	entries := m.audit[tenantID]
	limit = normalizedLimit(limit)
	if len(entries) < limit {
		limit = len(entries)
	}
	result := make([]core.AuditEntry, 0, limit)
	for i := len(entries) - 1; i >= 0 && len(result) < limit; i-- {
		result = append(result, entries[i])
	}
	return result
}

func (m *Memory) VerifyAudit(tenantID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	previous := ""
	for _, entry := range m.audit[tenantID] {
		if entry.PreviousHash != previous || auditHash(entry) != entry.Hash {
			return false
		}
		previous = entry.Hash
	}
	return previous == m.auditHeads[tenantID]
}

func auditHash(entry core.AuditEntry) string {
	metadata, _ := json.Marshal(entry.Metadata)
	value := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s|%s|%s",
		entry.PreviousHash, entry.ID, entry.TenantID, entry.Actor, entry.Action,
		entry.ResourceType, entry.ResourceID, entry.Outcome, entry.CreatedAt.UTC().Format(time.RFC3339Nano), metadata)
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func (m *Memory) Overview(tenantID string) map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()
	now := time.Now().UTC()
	dayAgo := now.Add(-24 * time.Hour)
	events24h := 0
	for _, event := range m.events[tenantID] {
		if event.IngestTime.After(dayAgo) {
			events24h++
		}
	}
	openAlerts, criticalAlerts, unassigned := 0, 0, 0
	severityCounts := map[core.Severity]int{}
	ruleCounts := map[string]int{}
	for _, alert := range m.alerts[tenantID] {
		if alert.Status != "CLOSED" {
			openAlerts++
			severityCounts[alert.Severity]++
			ruleCounts[alert.Rule.Title]++
			if alert.Severity == core.SeverityCritical {
				criticalAlerts++
			}
			if alert.Assignee == "" {
				unassigned++
			}
		}
	}
	activeIncidents := 0
	for _, incident := range m.incidents[tenantID] {
		if incident.Status != "CLOSED" {
			activeIncidents++
		}
	}
	topRules := make([]map[string]interface{}, 0, len(ruleCounts))
	for title, count := range ruleCounts {
		topRules = append(topRules, map[string]interface{}{"title": title, "count": count})
	}
	sort.Slice(topRules, func(i, j int) bool { return topRules[i]["count"].(int) > topRules[j]["count"].(int) })
	return map[string]interface{}{
		"tenant": map[string]string{"id": tenantID, "name": "K. Kulazhanov University"},
		"metrics": map[string]interface{}{
			"events_24h": events24h, "open_alerts": openAlerts, "critical_alerts": criticalAlerts,
			"unassigned_alerts": unassigned, "active_incidents": activeIncidents, "detection_latency_ms": 42,
		},
		"severity_distribution": []map[string]interface{}{
			{"severity": core.SeverityCritical, "count": severityCounts[core.SeverityCritical]},
			{"severity": core.SeverityHigh, "count": severityCounts[core.SeverityHigh]},
			{"severity": core.SeverityMedium, "count": severityCounts[core.SeverityMedium]},
			{"severity": core.SeverityLow, "count": severityCounts[core.SeverityLow]},
		},
		"top_rules": topRules,
		"platform": map[string]interface{}{
			"status": "OPERATIONAL", "profile": "embedded-dev", "ingest_eps": 0.4,
			"sources_healthy": 4, "sources_total": 5, "parser_errors_24h": 0,
		},
		"generated_at": now,
	}
}

func normalizedLimit(value int) int {
	if value <= 0 {
		return 100
	}
	if value > 500 {
		return 500
	}
	return value
}

func appendUnique(values []string, additions ...string) []string {
	seen := make(map[string]bool, len(values)+len(additions))
	for _, value := range values {
		seen[value] = true
	}
	for _, value := range additions {
		if value != "" && !seen[value] {
			values = append(values, value)
			seen[value] = true
		}
	}
	return values
}
