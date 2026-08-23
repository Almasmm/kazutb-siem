package cases

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/kcsp/platform/internal/core"
)

var (
	ErrInvalidCase       = errors.New("invalid case")
	ErrInvalidTransition = errors.New("invalid case transition")
	ErrClosureDetails    = errors.New("case closure summary is required")
	ErrTaskTransition    = errors.New("invalid case task transition")
)

type Repository interface {
	CreateCase(context.Context, core.Case) (core.Case, bool, error)
	GetCase(context.Context, string, string) (core.Case, error)
	ListCases(context.Context, string, core.CaseFilter) ([]core.Case, error)
	MutateCase(context.Context, string, string, int, func(*core.Case) error) (core.Case, error)
	GetIncident(context.Context, string, string) (core.Incident, error)
	ListEvidence(context.Context, string, core.EvidenceFilter) ([]core.EvidenceItem, error)
	AppendAudit(context.Context, core.AuditEntry) (core.AuditEntry, error)
}

type Service struct{ store Repository }

type CreateInput struct {
	Title        string
	Description  string
	Severity     core.Severity
	Owner        string
	IncidentIDs  []string
	Participants []ParticipantInput
	Observables  []ObservableInput
	RequestID    string
}

type Patch struct {
	Title          string
	Description    *string
	Status         string
	Severity       core.Severity
	Owner          string
	ClosureSummary string
	Version        int
	RequestID      string
}

type ParticipantInput struct {
	UserID string `json:"user_id"`
	Role   string `json:"role"`
}

type ObservableInput struct {
	Type   string `json:"type"`
	Value  string `json:"value"`
	Source string `json:"source"`
}

type TaskInput struct {
	Title       string     `json:"title"`
	Description string     `json:"description"`
	Assignee    string     `json:"assignee"`
	DueAt       *time.Time `json:"due_at"`
	Version     int        `json:"version"`
}

type TaskPatch struct {
	Status      string     `json:"status"`
	Assignee    string     `json:"assignee"`
	Description *string    `json:"description"`
	DueAt       *time.Time `json:"due_at"`
	Version     int        `json:"version"`
}

func NewService(repository Repository) *Service { return &Service{store: repository} }

func (s *Service) Cases(ctx context.Context, tenantID string, filter core.CaseFilter) ([]core.Case, error) {
	filter.Query = strings.TrimSpace(filter.Query)
	filter.Status = strings.ToUpper(strings.TrimSpace(filter.Status))
	filter.Severity = strings.ToUpper(strings.TrimSpace(filter.Severity))
	filter.Owner = strings.TrimSpace(filter.Owner)
	filter.IncidentID = strings.TrimSpace(filter.IncidentID)
	if filter.Limit < 0 || filter.Limit > 1000 {
		return nil, fmt.Errorf("%w: limit must be between 0 and 1000", ErrInvalidCase)
	}
	return s.store.ListCases(ctx, tenantID, filter)
}

func (s *Service) Case(ctx context.Context, tenantID, caseID string) (core.Case, error) {
	item, err := s.store.GetCase(ctx, tenantID, strings.TrimSpace(caseID))
	if err != nil {
		return core.Case{}, err
	}
	evidence, err := s.store.ListEvidence(ctx, tenantID, core.EvidenceFilter{CaseID: item.ID, Limit: 1000})
	if err != nil {
		return core.Case{}, err
	}
	item.EvidenceIDs = make([]string, 0, len(evidence))
	for _, value := range evidence {
		item.EvidenceIDs = append(item.EvidenceIDs, value.ID)
	}
	return item, nil
}

func (s *Service) Create(ctx context.Context, tenantID, actor string, input CreateInput) (core.Case, bool, error) {
	tenantID, actor, input.Title, input.Description = strings.TrimSpace(tenantID), strings.TrimSpace(actor), strings.TrimSpace(input.Title), strings.TrimSpace(input.Description)
	input.Owner, input.RequestID = strings.TrimSpace(input.Owner), strings.TrimSpace(input.RequestID)
	if tenantID == "" || actor == "" || input.Title == "" || len(input.Title) > 300 || len(input.Description) > 10000 || input.RequestID == "" {
		return core.Case{}, false, fmt.Errorf("%w: tenant, actor, title and request identity are required", ErrInvalidCase)
	}
	incidentIDs := uniqueSorted(input.IncidentIDs)
	severity := input.Severity
	if severity == "" {
		severity = core.SeverityMedium
	}
	for _, incidentID := range incidentIDs {
		incident, err := s.store.GetIncident(ctx, tenantID, incidentID)
		if err != nil {
			return core.Case{}, false, err
		}
		if core.SeverityRank(incident.Severity) > core.SeverityRank(severity) {
			severity = incident.Severity
		}
	}
	if !validSeverity(severity) {
		return core.Case{}, false, fmt.Errorf("%w: unsupported severity", ErrInvalidCase)
	}
	if input.Owner == "" {
		input.Owner = actor
	}
	now := time.Now().UTC()
	participants := []core.CaseParticipant{{UserID: input.Owner, Role: "OWNER", AddedBy: actor, AddedAt: now}}
	for _, value := range input.Participants {
		participants = appendParticipant(participants, value, actor, now)
	}
	observables := make([]core.CaseObservable, 0, len(input.Observables))
	for _, value := range input.Observables {
		observable, err := newObservable(value, actor, now)
		if err != nil {
			return core.Case{}, false, err
		}
		if !observableExists(observables, observable.Type, observable.Value) {
			observables = append(observables, observable)
		}
	}
	item := core.Case{
		ID: core.NewID("case"), TenantID: tenantID, RequestID: input.RequestID, Title: input.Title,
		Description: input.Description, Status: core.CaseStatusOpen, Severity: severity, Owner: input.Owner,
		IncidentIDs: incidentIDs, EvidenceIDs: []string{}, Participants: participants, Observables: observables,
		Tasks: []core.CaseTask{}, Comments: []core.CaseComment{}, History: []core.CaseHistoryEntry{
			newHistory("case.created", "Case opened", actor, map[string]interface{}{"incident_ids": incidentIDs}, now),
		},
		SLA: core.CaseSLA{DueAt: now.Add(caseWindow(severity))}, AllowedTransitions: AllowedTransitions(core.CaseStatusOpen),
		Version: 1, CreatedBy: actor, UpdatedBy: actor, CreatedAt: now, UpdatedAt: now,
	}
	created, duplicate, err := s.store.CreateCase(ctx, item)
	if err != nil {
		return core.Case{}, false, err
	}
	if duplicate {
		existing, lookupErr := s.Case(ctx, tenantID, created.ID)
		return existing, true, lookupErr
	}
	if err := s.audit(ctx, tenantID, actor, "case.created", created.ID, input.RequestID, map[string]interface{}{"incident_ids": incidentIDs, "severity": severity}); err != nil {
		return core.Case{}, false, err
	}
	return created, false, nil
}

func (s *Service) Update(ctx context.Context, tenantID, caseID, actor string, patch Patch) (core.Case, error) {
	now := time.Now().UTC()
	item, err := s.store.MutateCase(ctx, tenantID, caseID, patch.Version, func(item *core.Case) error {
		if title := strings.TrimSpace(patch.Title); title != "" {
			if len(title) > 300 {
				return fmt.Errorf("%w: title exceeds 300 characters", ErrInvalidCase)
			}
			item.Title = title
		}
		if patch.Description != nil {
			description := strings.TrimSpace(*patch.Description)
			if len(description) > 10000 {
				return fmt.Errorf("%w: description exceeds 10000 characters", ErrInvalidCase)
			}
			item.Description = description
		}
		if patch.Severity != "" {
			if !validSeverity(patch.Severity) {
				return fmt.Errorf("%w: unsupported severity", ErrInvalidCase)
			}
			item.Severity = patch.Severity
		}
		if owner := strings.TrimSpace(patch.Owner); owner != "" && owner != item.Owner {
			item.Owner = owner
			item.Participants = appendParticipant(item.Participants, ParticipantInput{UserID: owner, Role: "OWNER"}, actor, now)
			item.History = append(item.History, newHistory("case.assigned", "Case owner changed", actor, map[string]interface{}{"owner": owner}, now))
		}
		if patch.Status != "" {
			next := strings.ToUpper(strings.TrimSpace(patch.Status))
			if next != item.Status && !contains(AllowedTransitions(item.Status), next) {
				return fmt.Errorf("%w: %s -> %s", ErrInvalidTransition, item.Status, next)
			}
			if next == core.CaseStatusClosed {
				summary := strings.TrimSpace(patch.ClosureSummary)
				if summary == "" {
					return ErrClosureDetails
				}
				item.ClosureSummary = summary
				item.ClosedAt = &now
				item.SLA.Breached = now.After(item.SLA.DueAt)
			}
			if next != item.Status {
				previous := item.Status
				item.Status = next
				item.History = append(item.History, newHistory("case.status_changed", previous+" -> "+next, actor, nil, now))
			}
		}
		item.AllowedTransitions = AllowedTransitions(item.Status)
		item.UpdatedBy = actor
		return nil
	})
	if err != nil {
		return core.Case{}, err
	}
	if err := s.audit(ctx, tenantID, actor, "case.updated", item.ID, patch.RequestID, map[string]interface{}{"status": item.Status, "owner": item.Owner}); err != nil {
		return core.Case{}, err
	}
	return s.Case(ctx, tenantID, item.ID)
}

func (s *Service) AddComment(ctx context.Context, tenantID, caseID, actor, body, requestID string, version int) (core.Case, error) {
	body = strings.TrimSpace(body)
	if body == "" || len(body) > 10000 {
		return core.Case{}, fmt.Errorf("%w: comment must contain 1..10000 characters", ErrInvalidCase)
	}
	now := time.Now().UTC()
	item, err := s.store.MutateCase(ctx, tenantID, caseID, version, func(item *core.Case) error {
		comment := core.CaseComment{ID: core.NewID("cmt"), Body: body, Author: actor, CreatedAt: now}
		item.Comments = append(item.Comments, comment)
		item.History = append(item.History, newHistory("case.comment_added", "Investigation comment added", actor, map[string]interface{}{"comment_id": comment.ID}, now))
		item.UpdatedBy = actor
		return nil
	})
	if err != nil {
		return core.Case{}, err
	}
	if err := s.audit(ctx, tenantID, actor, "case.comment_added", item.ID, requestID, nil); err != nil {
		return core.Case{}, err
	}
	return s.Case(ctx, tenantID, item.ID)
}

func (s *Service) AddTask(ctx context.Context, tenantID, caseID, actor, requestID string, input TaskInput) (core.Case, error) {
	input.Title, input.Description, input.Assignee = strings.TrimSpace(input.Title), strings.TrimSpace(input.Description), strings.TrimSpace(input.Assignee)
	if input.Title == "" || len(input.Title) > 300 || len(input.Description) > 5000 {
		return core.Case{}, fmt.Errorf("%w: task title and bounded description are required", ErrInvalidCase)
	}
	now := time.Now().UTC()
	item, err := s.store.MutateCase(ctx, tenantID, caseID, input.Version, func(item *core.Case) error {
		task := core.CaseTask{ID: core.NewID("task"), Title: input.Title, Description: input.Description, Status: core.CaseTaskOpen, Assignee: input.Assignee, DueAt: input.DueAt, CreatedBy: actor, Version: 1, CreatedAt: now, UpdatedAt: now}
		item.Tasks = append(item.Tasks, task)
		item.History = append(item.History, newHistory("case.task_created", "Task created: "+task.Title, actor, map[string]interface{}{"task_id": task.ID}, now))
		item.UpdatedBy = actor
		return nil
	})
	if err != nil {
		return core.Case{}, err
	}
	if err := s.audit(ctx, tenantID, actor, "case.task_created", item.ID, requestID, nil); err != nil {
		return core.Case{}, err
	}
	return s.Case(ctx, tenantID, item.ID)
}

func (s *Service) UpdateTask(ctx context.Context, tenantID, caseID, taskID, actor, requestID string, patch TaskPatch) (core.Case, error) {
	now := time.Now().UTC()
	item, err := s.store.MutateCase(ctx, tenantID, caseID, patch.Version, func(item *core.Case) error {
		for index := range item.Tasks {
			task := &item.Tasks[index]
			if task.ID != taskID {
				continue
			}
			if patch.Status != "" {
				next := strings.ToUpper(strings.TrimSpace(patch.Status))
				if next != task.Status && !validTaskTransition(task.Status, next) {
					return fmt.Errorf("%w: %s -> %s", ErrTaskTransition, task.Status, next)
				}
				task.Status = next
				if next == core.CaseTaskDone {
					task.CompletedAt, task.CompletedBy = &now, actor
				}
			}
			if patch.Assignee != "" {
				task.Assignee = strings.TrimSpace(patch.Assignee)
			}
			if patch.Description != nil {
				task.Description = strings.TrimSpace(*patch.Description)
			}
			if patch.DueAt != nil {
				task.DueAt = patch.DueAt
			}
			task.Version++
			task.UpdatedAt = now
			item.History = append(item.History, newHistory("case.task_updated", "Task updated: "+task.Title, actor, map[string]interface{}{"task_id": task.ID, "status": task.Status}, now))
			item.UpdatedBy = actor
			return nil
		}
		return fmt.Errorf("%w: task does not exist", ErrInvalidCase)
	})
	if err != nil {
		return core.Case{}, err
	}
	if err := s.audit(ctx, tenantID, actor, "case.task_updated", item.ID, requestID, map[string]interface{}{"task_id": taskID}); err != nil {
		return core.Case{}, err
	}
	return s.Case(ctx, tenantID, item.ID)
}

func (s *Service) AddParticipant(ctx context.Context, tenantID, caseID, actor, requestID string, input ParticipantInput, version int) (core.Case, error) {
	now := time.Now().UTC()
	input.UserID, input.Role = strings.TrimSpace(input.UserID), strings.ToUpper(strings.TrimSpace(input.Role))
	if input.UserID == "" {
		return core.Case{}, fmt.Errorf("%w: participant identity is required", ErrInvalidCase)
	}
	item, err := s.store.MutateCase(ctx, tenantID, caseID, version, func(item *core.Case) error {
		item.Participants = appendParticipant(item.Participants, input, actor, now)
		item.History = append(item.History, newHistory("case.participant_added", "Participant added", actor, map[string]interface{}{"user_id": input.UserID, "role": input.Role}, now))
		item.UpdatedBy = actor
		return nil
	})
	if err != nil {
		return core.Case{}, err
	}
	if err := s.audit(ctx, tenantID, actor, "case.participant_added", item.ID, requestID, map[string]interface{}{"user_id": input.UserID}); err != nil {
		return core.Case{}, err
	}
	return s.Case(ctx, tenantID, item.ID)
}

func (s *Service) AddObservable(ctx context.Context, tenantID, caseID, actor, requestID string, input ObservableInput, version int) (core.Case, error) {
	now := time.Now().UTC()
	value, err := newObservable(input, actor, now)
	if err != nil {
		return core.Case{}, err
	}
	item, err := s.store.MutateCase(ctx, tenantID, caseID, version, func(item *core.Case) error {
		if !observableExists(item.Observables, value.Type, value.Value) {
			item.Observables = append(item.Observables, value)
		}
		item.History = append(item.History, newHistory("case.observable_added", "Observable added", actor, map[string]interface{}{"type": value.Type, "value": value.Value}, now))
		item.UpdatedBy = actor
		return nil
	})
	if err != nil {
		return core.Case{}, err
	}
	if err := s.audit(ctx, tenantID, actor, "case.observable_added", item.ID, requestID, map[string]interface{}{"observable_id": value.ID}); err != nil {
		return core.Case{}, err
	}
	return s.Case(ctx, tenantID, item.ID)
}

func (s *Service) LinkIncident(ctx context.Context, tenantID, caseID, incidentID, actor, requestID string, version int) (core.Case, error) {
	incidentID = strings.TrimSpace(incidentID)
	if _, err := s.store.GetIncident(ctx, tenantID, incidentID); err != nil {
		return core.Case{}, err
	}
	now := time.Now().UTC()
	item, err := s.store.MutateCase(ctx, tenantID, caseID, version, func(item *core.Case) error {
		item.IncidentIDs = appendUnique(item.IncidentIDs, incidentID)
		item.History = append(item.History, newHistory("case.incident_linked", "Incident linked", actor, map[string]interface{}{"incident_id": incidentID}, now))
		item.UpdatedBy = actor
		return nil
	})
	if err != nil {
		return core.Case{}, err
	}
	if err := s.audit(ctx, tenantID, actor, "case.incident_linked", item.ID, requestID, map[string]interface{}{"incident_id": incidentID}); err != nil {
		return core.Case{}, err
	}
	return s.Case(ctx, tenantID, item.ID)
}

func AllowedTransitions(status string) []string {
	values := map[string][]string{core.CaseStatusOpen: {core.CaseStatusInvestigation, core.CaseStatusClosed}, core.CaseStatusInvestigation: {core.CaseStatusResponse, core.CaseStatusClosed}, core.CaseStatusResponse: {core.CaseStatusInvestigation, core.CaseStatusClosed}, core.CaseStatusClosed: {}}
	return append([]string(nil), values[strings.ToUpper(status)]...)
}

func (s *Service) audit(ctx context.Context, tenantID, actor, action, caseID, requestID string, metadata map[string]interface{}) error {
	_, err := s.store.AppendAudit(ctx, core.AuditEntry{TenantID: tenantID, Actor: actor, Action: action, ResourceType: "case", ResourceID: caseID, Outcome: "SUCCESS", RequestID: requestID, Metadata: metadata})
	if err != nil {
		return fmt.Errorf("append case audit: %w", err)
	}
	return nil
}

func newHistory(action, message, actor string, metadata map[string]interface{}, at time.Time) core.CaseHistoryEntry {
	return core.CaseHistoryEntry{ID: core.NewID("hist"), Action: action, Message: message, Actor: actor, Metadata: metadata, CreatedAt: at}
}
func newObservable(input ObservableInput, actor string, now time.Time) (core.CaseObservable, error) {
	input.Type, input.Value, input.Source = strings.ToUpper(strings.TrimSpace(input.Type)), strings.TrimSpace(input.Value), strings.TrimSpace(input.Source)
	if input.Type == "" || input.Value == "" || len(input.Value) > 2048 {
		return core.CaseObservable{}, fmt.Errorf("%w: observable type and bounded value are required", ErrInvalidCase)
	}
	return core.CaseObservable{ID: core.NewID("obs"), Type: input.Type, Value: input.Value, Source: input.Source, AddedBy: actor, CreatedAt: now}, nil
}
func appendParticipant(values []core.CaseParticipant, input ParticipantInput, actor string, now time.Time) []core.CaseParticipant {
	input.UserID, input.Role = strings.TrimSpace(input.UserID), strings.ToUpper(strings.TrimSpace(input.Role))
	if input.UserID == "" {
		return values
	}
	if input.Role == "" {
		input.Role = "MEMBER"
	}
	for index := range values {
		if values[index].UserID == input.UserID {
			values[index].Role = input.Role
			return values
		}
	}
	return append(values, core.CaseParticipant{UserID: input.UserID, Role: input.Role, AddedBy: actor, AddedAt: now})
}
func observableExists(values []core.CaseObservable, kind, value string) bool {
	for _, item := range values {
		if item.Type == kind && strings.EqualFold(item.Value, value) {
			return true
		}
	}
	return false
}
func validTaskTransition(current, next string) bool {
	allowed := map[string]map[string]bool{core.CaseTaskOpen: {core.CaseTaskInProgress: true, core.CaseTaskDone: true, core.CaseTaskCancelled: true}, core.CaseTaskInProgress: {core.CaseTaskDone: true, core.CaseTaskCancelled: true}, core.CaseTaskDone: {}, core.CaseTaskCancelled: {}}
	return allowed[current][next]
}
func validSeverity(value core.Severity) bool {
	return value == core.SeverityCritical || value == core.SeverityHigh || value == core.SeverityMedium || value == core.SeverityLow || value == core.SeverityInformational
}
func caseWindow(value core.Severity) time.Duration {
	switch value {
	case core.SeverityCritical:
		return 4 * time.Hour
	case core.SeverityHigh:
		return 12 * time.Hour
	case core.SeverityMedium:
		return 48 * time.Hour
	default:
		return 7 * 24 * time.Hour
	}
}
func uniqueSorted(values []string) []string {
	result := appendUnique(nil, values...)
	sort.Strings(result)
	return result
}
func appendUnique(values []string, additions ...string) []string {
	seen := map[string]bool{}
	for _, value := range values {
		seen[value] = true
	}
	for _, value := range additions {
		value = strings.TrimSpace(value)
		if value != "" && !seen[value] {
			values = append(values, value)
			seen[value] = true
		}
	}
	return values
}
func contains(values []string, candidate string) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}
