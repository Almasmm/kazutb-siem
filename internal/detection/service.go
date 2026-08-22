package detection

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kcsp/platform/internal/core"
)

var (
	ErrValidationFailed = errors.New("detection validation failed")
	ErrInvalidState     = errors.New("invalid detection lifecycle state")
)

type ContentRepository interface {
	CreateDetectionDraft(context.Context, core.DetectionContent) (core.DetectionContent, error)
	DetectionContent(context.Context, string, string, string) (core.DetectionContent, error)
	ListDetectionContent(context.Context, string) ([]core.DetectionContent, error)
	SaveDetectionValidation(context.Context, core.DetectionContent, core.DetectionRule, core.DetectionValidationReport) (core.DetectionContent, error)
	PublishDetectionContent(context.Context, string, string, string) (core.DetectionContent, error)
	DisableDetectionContent(context.Context, string, string) (core.DetectionContent, error)
	RollbackDetectionContent(context.Context, string, string) (core.DetectionContent, error)
	PublishedDetectionContent(context.Context, string) ([]core.DetectionContent, error)
	ReplayDetectionEvents(context.Context, string, time.Time, time.Time, int) ([]core.CanonicalEvent, error)
}

type Service struct {
	repository ContentRepository
}

func NewService(repository ContentRepository) *Service {
	return &Service{repository: repository}
}

func (s *Service) CreateDraft(ctx context.Context, content core.DetectionContent) (core.DetectionContent, error) {
	content.TenantID = strings.TrimSpace(content.TenantID)
	content.RuleID = strings.TrimSpace(content.RuleID)
	content.Version = strings.TrimSpace(content.Version)
	content.SigmaYAML = strings.TrimSpace(content.SigmaYAML)
	content.CreatedBy = strings.TrimSpace(content.CreatedBy)
	if content.TenantID == "" || content.RuleID == "" || content.Version == "" || content.SigmaYAML == "" || content.CreatedBy == "" {
		return core.DetectionContent{}, fmt.Errorf("%w: tenant, rule ID, version, Sigma YAML and creator are required", ErrInvalidRule)
	}
	if len(content.RuleID) > 128 || len(content.Version) > 64 || len(content.SigmaYAML) > 512<<10 {
		return core.DetectionContent{}, fmt.Errorf("%w: detection content exceeds allowed size", ErrInvalidRule)
	}
	if content.PerformanceBudgetMicros <= 0 {
		content.PerformanceBudgetMicros = 500
	}
	content.State = "DRAFT"
	content.Rule = core.DetectionRule{}
	content.Validation = core.DetectionValidationReport{}
	return s.repository.CreateDetectionDraft(ctx, content)
}

func (s *Service) Validate(ctx context.Context, tenantID, ruleID, version string) (core.DetectionContent, error) {
	content, err := s.repository.DetectionContent(ctx, tenantID, ruleID, version)
	if err != nil {
		return core.DetectionContent{}, err
	}
	started := time.Now()
	report := core.DetectionValidationReport{
		CompilerVersion: CompilerVersion, PositiveTotal: len(content.PositiveTests), NegativeTotal: len(content.NegativeTests),
		Errors: []string{}, ValidatedAt: time.Now().UTC(),
	}
	compiled, compileErr := Compile(content)
	if compileErr != nil {
		report.Errors = append(report.Errors, compileErr.Error())
	}
	if len(content.PositiveTests) == 0 {
		report.Errors = append(report.Errors, "at least one positive test is required")
	}
	if len(content.NegativeTests) == 0 {
		report.Errors = append(report.Errors, "at least one negative test is required")
	}
	if compiled != nil {
		for _, sample := range content.PositiveTests {
			evaluationStarted := time.Now()
			matched, _ := compiled.Evaluate(sample.Event)
			if matched {
				report.PositivePassed++
			} else {
				report.Errors = append(report.Errors, fmt.Sprintf("positive sample %q did not match", sample.Name))
			}
			if elapsed := time.Since(evaluationStarted).Microseconds(); elapsed > content.PerformanceBudgetMicros {
				report.Errors = append(report.Errors, fmt.Sprintf("positive sample %q exceeded %d microsecond budget (%d)", sample.Name, content.PerformanceBudgetMicros, elapsed))
			}
		}
		for _, sample := range content.NegativeTests {
			evaluationStarted := time.Now()
			matched, _ := compiled.Evaluate(sample.Event)
			if !matched {
				report.NegativePassed++
			} else {
				report.Errors = append(report.Errors, fmt.Sprintf("negative sample %q matched", sample.Name))
			}
			if elapsed := time.Since(evaluationStarted).Microseconds(); elapsed > content.PerformanceBudgetMicros {
				report.Errors = append(report.Errors, fmt.Sprintf("negative sample %q exceeded %d microsecond budget (%d)", sample.Name, content.PerformanceBudgetMicros, elapsed))
			}
		}
	}
	report.DurationMicros = time.Since(started).Microseconds()
	report.Valid = len(report.Errors) == 0
	rule := core.DetectionRule{}
	if compiled != nil {
		rule = compiled.Rule
		rule.State = map[bool]string{true: "VALIDATED", false: "DRAFT"}[report.Valid]
		rule.UpdatedAt = report.ValidatedAt
	}
	updated, saveErr := s.repository.SaveDetectionValidation(ctx, content, rule, report)
	if saveErr != nil {
		return core.DetectionContent{}, saveErr
	}
	if !report.Valid {
		return updated, fmt.Errorf("%w: %s", ErrValidationFailed, strings.Join(report.Errors, "; "))
	}
	return updated, nil
}

func (s *Service) Publish(ctx context.Context, tenantID, ruleID, version string) (core.DetectionContent, error) {
	return s.repository.PublishDetectionContent(ctx, tenantID, ruleID, version)
}

func (s *Service) Disable(ctx context.Context, tenantID, ruleID string) (core.DetectionContent, error) {
	return s.repository.DisableDetectionContent(ctx, tenantID, ruleID)
}

func (s *Service) Rollback(ctx context.Context, tenantID, ruleID string) (core.DetectionContent, error) {
	return s.repository.RollbackDetectionContent(ctx, tenantID, ruleID)
}

func (s *Service) List(ctx context.Context, tenantID string) ([]core.DetectionContent, error) {
	return s.repository.ListDetectionContent(ctx, tenantID)
}

func (s *Service) Simulate(ctx context.Context, tenantID, ruleID, version string, event core.CanonicalEvent) (bool, []string, error) {
	content, err := s.repository.DetectionContent(ctx, tenantID, ruleID, version)
	if err != nil {
		return false, nil, err
	}
	compiled, err := Compile(content)
	if err != nil {
		return false, nil, err
	}
	matched, fields := compiled.Evaluate(event)
	return matched, fields, nil
}

func (s *Service) Replay(ctx context.Context, tenantID, ruleID, version string, start, end time.Time, limit int) (core.DetectionReplayReport, error) {
	if start.IsZero() || end.IsZero() || !start.Before(end) {
		return core.DetectionReplayReport{}, fmt.Errorf("%w: replay requires a valid start/end range", ErrInvalidRule)
	}
	if end.Sub(start) > 31*24*time.Hour {
		return core.DetectionReplayReport{}, fmt.Errorf("%w: replay range cannot exceed 31 days", ErrInvalidRule)
	}
	if limit <= 0 {
		limit = 10_000
	}
	if limit > 100_000 {
		return core.DetectionReplayReport{}, fmt.Errorf("%w: replay limit cannot exceed 100000 events", ErrInvalidRule)
	}
	content, err := s.repository.DetectionContent(ctx, tenantID, ruleID, version)
	if err != nil {
		return core.DetectionReplayReport{}, err
	}
	compiled, err := Compile(content)
	if err != nil {
		return core.DetectionReplayReport{}, err
	}
	started := time.Now()
	events, err := s.repository.ReplayDetectionEvents(ctx, tenantID, start.UTC(), end.UTC(), limit+1)
	if err != nil {
		return core.DetectionReplayReport{}, err
	}
	report := core.DetectionReplayReport{RuleID: ruleID, Version: version, Start: start.UTC(), End: end.UTC()}
	if len(events) > limit {
		events = events[:limit]
		report.Truncated = true
	}
	report.EventsScanned = len(events)
	for _, event := range events {
		matched, _ := compiled.Evaluate(event)
		if !matched {
			continue
		}
		report.Matches++
		if len(report.SampleEventIDs) < 100 {
			report.SampleEventIDs = append(report.SampleEventIDs, event.ID)
		}
	}
	report.DurationMicros = time.Since(started).Microseconds()
	return report, nil
}
