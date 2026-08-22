package soc

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/store"
)

var (
	ErrInvalidTransition = errors.New("invalid state transition")
	ErrClosureDetails    = errors.New("closure requires disposition and reason")
	ErrNoAlerts          = errors.New("at least one alert is required")
)

type Service struct {
	store Repository
}

// Repository is the transactional SOC port. A production implementation must
// make each mutation and its audit record atomic in PostgreSQL.
type Repository interface {
	ListIncidents(string, store.IncidentFilter) []core.Incident
	GetAlert(string, string) (core.Alert, error)
	MutateAlert(string, string, int, func(*core.Alert) error) (core.Alert, error)
	CreateIncident(core.Incident) (core.Incident, error)
	MutateIncident(string, string, int, func(*core.Incident) error) (core.Incident, error)
	AppendAudit(core.AuditEntry) core.AuditEntry
}

type AlertPatch struct {
	Status      string
	Assignee    string
	Disposition string
	Comment     string
	Version     int
}

type CreateIncidentInput struct {
	Title     string
	Summary   string
	Assignee  string
	AlertIDs  []string
	RequestID string
}

type IncidentPatch struct {
	Status        string
	Assignee      string
	Disposition   string
	ClosureReason string
	Comment       string
	Version       int
	RequestID     string
}

func New(memory Repository) *Service {
	return &Service{store: memory}
}

func (s *Service) UpdateAlert(tenantID, alertID, actor, requestID string, patch AlertPatch) (core.Alert, error) {
	now := time.Now().UTC()
	alert, err := s.store.MutateAlert(tenantID, alertID, patch.Version, func(alert *core.Alert) error {
		if patch.Status != "" {
			next := strings.ToUpper(patch.Status)
			if !validAlertTransition(alert.Status, next) {
				return fmt.Errorf("%w: alert %s -> %s", ErrInvalidTransition, alert.Status, next)
			}
			if next == "CLOSED" && strings.TrimSpace(patch.Disposition) == "" {
				return ErrClosureDetails
			}
			alert.Status = next
			if next == "ACKNOWLEDGED" || next == "IN_PROGRESS" || next == "CLOSED" {
				if alert.SLA.Acknowledged == nil {
					acknowledged := now
					alert.SLA.Acknowledged = &acknowledged
					alert.SLA.Breached = acknowledged.After(alert.SLA.AcknowledgeBy)
				}
			}
		}
		if patch.Assignee != "" {
			alert.Assignee = strings.TrimSpace(patch.Assignee)
		}
		if patch.Disposition != "" {
			alert.Disposition = strings.ToUpper(patch.Disposition)
		}
		return nil
	})
	if err != nil {
		return core.Alert{}, err
	}
	s.store.AppendAudit(core.AuditEntry{
		TenantID: tenantID, Actor: actor, Action: "alert.triaged", ResourceType: "alert", ResourceID: alert.ID,
		Outcome: "success", RequestID: requestID,
		Metadata: map[string]interface{}{"status": alert.Status, "assignee": alert.Assignee, "disposition": alert.Disposition, "comment": patch.Comment},
	})
	return alert, nil
}

func validAlertTransition(current, next string) bool {
	if current == next {
		return true
	}
	allowed := map[string]map[string]bool{
		"NEW":          {"ACKNOWLEDGED": true, "IN_PROGRESS": true, "CLOSED": true},
		"ACKNOWLEDGED": {"IN_PROGRESS": true, "CLOSED": true},
		"IN_PROGRESS":  {"CLOSED": true},
		"CLOSED":       {},
	}
	return allowed[current][next]
}

func (s *Service) CreateIncident(tenantID, actor string, input CreateIncidentInput) (core.Incident, bool, error) {
	if len(input.AlertIDs) == 0 {
		return core.Incident{}, false, ErrNoAlerts
	}
	alertIDs := uniqueSorted(input.AlertIDs)
	for _, existing := range s.store.ListIncidents(tenantID, store.IncidentFilter{Limit: 500}) {
		if stringSlicesEqual(uniqueSorted(existing.AlertIDs), alertIDs) {
			return existing, true, nil
		}
	}

	alerts := make([]core.Alert, 0, len(alertIDs))
	severity := core.SeverityInformational
	riskScore := 0
	findingIDs, eventIDs, mitre := []string{}, []string{}, []string{}
	entities := []core.EntitySummary{}
	for _, alertID := range alertIDs {
		alert, err := s.store.GetAlert(tenantID, alertID)
		if err != nil {
			return core.Incident{}, false, err
		}
		alerts = append(alerts, alert)
		if core.SeverityRank(alert.Severity) > core.SeverityRank(severity) {
			severity = alert.Severity
		}
		if alert.RiskScore > riskScore {
			riskScore = alert.RiskScore
		}
		findingIDs = appendUnique(findingIDs, alert.FindingIDs...)
		eventIDs = appendUnique(eventIDs, alert.EventIDs...)
		mitre = appendUnique(mitre, alert.MITRE...)
		if alert.Entity.Name != "" && !entityExists(entities, alert.Entity) {
			entities = append(entities, alert.Entity)
		}
	}
	now := time.Now().UTC()
	title := strings.TrimSpace(input.Title)
	if title == "" {
		title = alerts[0].Title
	}
	incident := core.Incident{
		ID: core.NewID("inc"), TenantID: tenantID, Title: title, Summary: strings.TrimSpace(input.Summary),
		Severity: severity, Status: "NEW", Assignee: strings.TrimSpace(input.Assignee), AlertIDs: alertIDs,
		FindingIDs: findingIDs, EventIDs: eventIDs, Entities: entities, MITRE: mitre, RiskScore: riskScore,
		Timeline:           []core.TimelineEntry{{ID: core.NewID("tim"), Type: "incident.created", Message: "Incident created from SOC alert", Actor: actor, CreatedAt: now}},
		SLA:                core.SLAInfo{AcknowledgeBy: now.Add(acknowledgementWindow(severity))},
		AllowedTransitions: AllowedTransitions("NEW"), Version: 1, CreatedAt: now, UpdatedAt: now,
	}
	created, err := s.store.CreateIncident(incident)
	if err != nil {
		return core.Incident{}, false, err
	}
	for _, alert := range alerts {
		_, _ = s.store.MutateAlert(tenantID, alert.ID, 0, func(value *core.Alert) error {
			if value.Status == "NEW" || value.Status == "ACKNOWLEDGED" {
				value.Status = "IN_PROGRESS"
			}
			if value.Assignee == "" {
				value.Assignee = input.Assignee
			}
			return nil
		})
	}
	s.store.AppendAudit(core.AuditEntry{
		TenantID: tenantID, Actor: actor, Action: "incident.created", ResourceType: "incident", ResourceID: created.ID,
		Outcome: "success", RequestID: input.RequestID,
		Metadata: map[string]interface{}{"alert_ids": alertIDs, "severity": severity, "risk_score": riskScore},
	})
	return created, false, nil
}

func (s *Service) UpdateIncident(tenantID, incidentID, actor string, patch IncidentPatch) (core.Incident, error) {
	now := time.Now().UTC()
	incident, err := s.store.MutateIncident(tenantID, incidentID, patch.Version, func(incident *core.Incident) error {
		previous := incident.Status
		if patch.Status != "" {
			next := strings.ToUpper(patch.Status)
			if !contains(AllowedTransitions(previous), next) && previous != next {
				return fmt.Errorf("%w: incident %s -> %s", ErrInvalidTransition, previous, next)
			}
			if next == "CLOSED" {
				disposition := firstNonEmpty(patch.Disposition, incident.Disposition)
				reason := firstNonEmpty(patch.ClosureReason, incident.ClosureReason)
				if disposition == "" || reason == "" {
					return ErrClosureDetails
				}
				incident.Disposition = strings.ToUpper(disposition)
				incident.ClosureReason = reason
			}
			incident.Status = next
			if next != previous {
				incident.Timeline = append(incident.Timeline, core.TimelineEntry{
					ID: core.NewID("tim"), Type: "incident.status_changed",
					Message: previous + " → " + next, Actor: actor, CreatedAt: now,
				})
			}
			if next != "NEW" && incident.SLA.Acknowledged == nil {
				acknowledged := now
				incident.SLA.Acknowledged = &acknowledged
				incident.SLA.Breached = acknowledged.After(incident.SLA.AcknowledgeBy)
			}
		}
		if patch.Assignee != "" && patch.Assignee != incident.Assignee {
			incident.Assignee = strings.TrimSpace(patch.Assignee)
			incident.Timeline = append(incident.Timeline, core.TimelineEntry{
				ID: core.NewID("tim"), Type: "incident.assigned", Message: "Assigned to " + incident.Assignee, Actor: actor, CreatedAt: now,
			})
		}
		if patch.Disposition != "" {
			incident.Disposition = strings.ToUpper(patch.Disposition)
		}
		if patch.ClosureReason != "" {
			incident.ClosureReason = strings.TrimSpace(patch.ClosureReason)
		}
		if strings.TrimSpace(patch.Comment) != "" {
			incident.Timeline = append(incident.Timeline, core.TimelineEntry{
				ID: core.NewID("tim"), Type: "comment", Message: strings.TrimSpace(patch.Comment), Actor: actor, CreatedAt: now,
			})
		}
		incident.AllowedTransitions = AllowedTransitions(incident.Status)
		return nil
	})
	if err != nil {
		return core.Incident{}, err
	}
	s.store.AppendAudit(core.AuditEntry{
		TenantID: tenantID, Actor: actor, Action: "incident.updated", ResourceType: "incident", ResourceID: incident.ID,
		Outcome: "success", RequestID: patch.RequestID,
		Metadata: map[string]interface{}{"status": incident.Status, "assignee": incident.Assignee, "disposition": incident.Disposition},
	})
	return incident, nil
}

func AllowedTransitions(status string) []string {
	transitions := map[string][]string{
		"NEW":           {"TRIAGE"},
		"TRIAGE":        {"INVESTIGATION", "CLOSED"},
		"INVESTIGATION": {"CONTAINMENT", "RECOVERY", "CLOSED"},
		"CONTAINMENT":   {"ERADICATION", "RECOVERY"},
		"ERADICATION":   {"RECOVERY"},
		"RECOVERY":      {"CLOSED"},
		"CLOSED":        {},
	}
	return append([]string(nil), transitions[strings.ToUpper(status)]...)
}

func acknowledgementWindow(severity core.Severity) time.Duration {
	switch severity {
	case core.SeverityCritical:
		return 15 * time.Minute
	case core.SeverityHigh:
		return 30 * time.Minute
	case core.SeverityMedium:
		return 4 * time.Hour
	default:
		return 24 * time.Hour
	}
}

func appendUnique(values []string, additions ...string) []string {
	seen := map[string]bool{}
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

func uniqueSorted(values []string) []string {
	result := appendUnique(nil, values...)
	sort.Strings(result)
	return result
}

func stringSlicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func entityExists(values []core.EntitySummary, candidate core.EntitySummary) bool {
	for _, value := range values {
		if value.Type == candidate.Type && value.Name == candidate.Name {
			return true
		}
	}
	return false
}

func contains(values []string, candidate string) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
