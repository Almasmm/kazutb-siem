package parser

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/ingest"
)

var (
	ErrInvalidDefinition = errors.New("invalid parser definition")
	ErrValidationFailed  = errors.New("parser validation failed")
)

type StudioRepository interface {
	CreateParserDraft(context.Context, core.ParserContent) (core.ParserContent, error)
	ParserContent(context.Context, string, string, int) (core.ParserContent, error)
	ListParserContent(context.Context, string) ([]core.ParserContent, error)
	SaveParserValidation(context.Context, core.ParserContent) (core.ParserContent, error)
	PublishParserContent(context.Context, string, string, int) (core.ParserContent, error)
	DisableParserContent(context.Context, string, string) (core.ParserContent, error)
}

type StudioService struct{ repository StudioRepository }

type ParserDraft struct {
	ParserID  string          `json:"parser_id,omitempty"`
	Name      string          `json:"name"`
	Spec      core.ParserSpec `json:"spec"`
	RequestID string          `json:"request_id,omitempty"`
}

func NewStudioService(repository StudioRepository) *StudioService {
	return &StudioService{repository: repository}
}

func (s *StudioService) List(ctx context.Context, tenantID string) ([]core.ParserContent, error) {
	return s.repository.ListParserContent(ctx, tenantID)
}

func (s *StudioService) Content(ctx context.Context, tenantID, parserID string, version int) (core.ParserContent, error) {
	return s.repository.ParserContent(ctx, tenantID, strings.TrimSpace(parserID), version)
}

func (s *StudioService) CreateDraft(ctx context.Context, tenantID, actor string, draft ParserDraft) (core.ParserContent, error) {
	draft.Name = strings.TrimSpace(draft.Name)
	if draft.Name == "" || len(draft.Name) > 160 {
		return core.ParserContent{}, fmt.Errorf("%w: name is required and must not exceed 160 characters", ErrInvalidDefinition)
	}
	draft.Spec = NormalizeSpec(draft.Spec)
	report := ValidateDefinition(draft.Spec)
	if len(report.Errors) > 0 {
		return core.ParserContent{}, fmt.Errorf("%w: %s", ErrInvalidDefinition, strings.Join(report.Errors, "; "))
	}
	parserID := strings.TrimSpace(draft.ParserID)
	if parserID == "" {
		parserID = core.NewID("prs")
	}
	return s.repository.CreateParserDraft(ctx, core.ParserContent{
		ParserID: parserID, TenantID: tenantID, Name: draft.Name, State: core.ParserStateDraft,
		Spec: draft.Spec, Validation: core.ParserValidationReport{}, CreatedBy: actor, RequestID: strings.TrimSpace(draft.RequestID),
	})
}

func (s *StudioService) Validate(ctx context.Context, tenantID, parserID string, version int) (core.ParserContent, error) {
	content, err := s.Content(ctx, tenantID, parserID, version)
	if err != nil {
		return core.ParserContent{}, err
	}
	content.Validation = ValidateContent(content)
	updated, saveErr := s.repository.SaveParserValidation(ctx, content)
	if saveErr != nil {
		return core.ParserContent{}, saveErr
	}
	if !updated.Validation.Valid {
		return updated, fmt.Errorf("%w: %s", ErrValidationFailed, strings.Join(updated.Validation.Errors, "; "))
	}
	return updated, nil
}

func (s *StudioService) Publish(ctx context.Context, tenantID, parserID string, version int) (core.ParserContent, error) {
	content, err := s.Content(ctx, tenantID, parserID, version)
	if err != nil {
		return core.ParserContent{}, err
	}
	if !content.Validation.Valid {
		return core.ParserContent{}, ErrValidationFailed
	}
	return s.repository.PublishParserContent(ctx, tenantID, parserID, version)
}

func (s *StudioService) Disable(ctx context.Context, tenantID, parserID string) (core.ParserContent, error) {
	return s.repository.DisableParserContent(ctx, tenantID, parserID)
}

func (s *StudioService) Simulate(ctx context.Context, tenantID, parserID string, version int, payload string) (core.ParserSimulation, error) {
	if len(payload) == 0 || len(payload) > 1<<20 {
		return core.ParserSimulation{}, fmt.Errorf("%w: sample payload must be between 1 byte and 1 MiB", ErrInvalidDefinition)
	}
	content, err := s.Content(ctx, tenantID, parserID, version)
	if err != nil {
		return core.ParserSimulation{}, err
	}
	compiled, err := Compile(content)
	if err != nil {
		return core.ParserSimulation{}, err
	}
	envelope := ingest.RawEnvelope{TenantID: tenantID, CollectorID: "parser-studio", EventID: core.NewID("evt"), Format: content.Spec.Format, RawPayload: []byte(payload)}
	event, err := compiled.Parse(ctx, envelope)
	if err != nil {
		return core.ParserSimulation{}, err
	}
	fields := map[string]string{}
	for target := range allowedTargets {
		if value, ok := EventField(event, target); ok && value != "" {
			fields[target] = value
		}
	}
	return core.ParserSimulation{ParserID: parserID, Version: version, Event: event, Fields: fields}, nil
}

func BuiltInDescriptors() []Descriptor { return NewRegistry().Descriptors() }
