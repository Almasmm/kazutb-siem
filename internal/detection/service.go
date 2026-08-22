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
	var evaluate sampleEvaluator
	if compiled != nil {
		evaluate, compileErr = s.sampleEvaluator(ctx, content, compiled)
		if compileErr != nil {
			report.Errors = append(report.Errors, compileErr.Error())
		}
	}
	if len(content.PositiveTests) == 0 {
		report.Errors = append(report.Errors, "at least one positive test is required")
	}
	if len(content.NegativeTests) == 0 {
		report.Errors = append(report.Errors, "at least one negative test is required")
	}
	if evaluate != nil {
		for _, sample := range content.PositiveTests {
			evaluationStarted := time.Now()
			matched, evaluationErr := evaluate(sample)
			if evaluationErr != nil {
				report.Errors = append(report.Errors, fmt.Sprintf("positive sample %q failed: %v", sample.Name, evaluationErr))
			} else if matched {
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
			matched, evaluationErr := evaluate(sample)
			if evaluationErr != nil {
				report.Errors = append(report.Errors, fmt.Sprintf("negative sample %q failed: %v", sample.Name, evaluationErr))
			} else if !matched {
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

type sampleEvaluator func(core.DetectionSample) (bool, error)

func (s *Service) sampleEvaluator(ctx context.Context, content core.DetectionContent, compiled *CompiledRule) (sampleEvaluator, error) {
	spec, isCorrelation := compiled.CorrelationSpec()
	if !isCorrelation {
		return func(sample core.DetectionSample) (bool, error) {
			events := detectionSampleEvents(sample)
			for _, event := range events {
				matched, _ := compiled.Evaluate(event)
				if matched {
					return true, nil
				}
			}
			return false, nil
		}, nil
	}
	published, err := s.repository.PublishedDetectionContent(ctx, content.TenantID)
	if err != nil {
		return nil, fmt.Errorf("load correlation dependencies: %w", err)
	}
	dependencies := map[string]*CompiledRule{}
	wanted := map[string]bool{}
	for _, ruleID := range spec.Rules {
		wanted[ruleID] = true
	}
	for _, dependency := range published {
		if !wanted[dependency.RuleID] {
			continue
		}
		compiledDependency, err := Compile(dependency)
		if err != nil {
			return nil, fmt.Errorf("compile correlation dependency %s: %w", dependency.RuleID, err)
		}
		if compiledDependency.IsCorrelation() {
			return nil, fmt.Errorf("%w: correlation-of-correlation reference %q is not supported", ErrInvalidRule, dependency.RuleID)
		}
		dependencies[dependency.RuleID] = compiledDependency
	}
	for _, ruleID := range spec.Rules {
		if dependencies[ruleID] == nil {
			return nil, fmt.Errorf("%w: correlation dependency %q must be published", ErrInvalidRule, ruleID)
		}
	}
	return func(sample core.DetectionSample) (bool, error) {
		memory := NewMemoryCorrelationStore()
		for index, event := range detectionSampleEvents(sample) {
			if event.ID == "" {
				event.ID = fmt.Sprintf("validation-%s-%d", content.RuleID, index)
			}
			if event.EventTime.IsZero() {
				event.EventTime = time.Unix(int64(index+1), 0).UTC()
			}
			event.TenantID = content.TenantID
			matchedRules := []string{}
			for _, ruleID := range spec.Rules {
				matched, _ := dependencies[ruleID].Evaluate(event)
				if matched {
					matchedRules = append(matchedRules, ruleID)
				}
			}
			if len(matchedRules) == 0 {
				continue
			}
			groupKey, ok := CorrelationGroup(event, spec.GroupBy)
			if !ok {
				continue
			}
			value := ""
			if spec.Type == core.CorrelationValueCount {
				value, ok = CorrelationValue(event, spec.ValueField)
				if !ok {
					continue
				}
			}
			result, err := memory.ObserveCorrelation(ctx, core.CorrelationObservation{
				TenantID: content.TenantID, RuleID: content.RuleID, RuleVersion: content.Version,
				GroupKey: groupKey, SourceRuleIDs: matchedRules, EventID: event.ID, EventTime: event.EventTime,
				Value: value, Spec: spec,
			})
			if err != nil {
				return false, err
			}
			if result.Triggered {
				return true, nil
			}
		}
		return false, nil
	}, nil
}

func detectionSampleEvents(sample core.DetectionSample) []core.CanonicalEvent {
	if len(sample.Events) > 0 {
		return sample.Events
	}
	return []core.CanonicalEvent{sample.Event}
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
