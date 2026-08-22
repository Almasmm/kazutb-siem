package soar

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/kcsp/platform/internal/core"
)

type Store interface {
	CreateSOARPlaybook(context.Context, core.SOARPlaybook, core.SOARPlaybookVersion) (core.SOARPlaybookDetails, error)
	CreateSOARPlaybookVersion(context.Context, string, string, string, core.SOARPlaybookSpec, core.SOARValidationReport) (core.SOARPlaybookVersion, error)
	GetSOARPlaybook(context.Context, string, string) (core.SOARPlaybookDetails, error)
	ListSOARPlaybooks(context.Context, string) ([]core.SOARPlaybook, error)
	SaveSOARValidation(context.Context, string, string, int, core.SOARValidationReport) (core.SOARPlaybookVersion, error)
	PublishSOARPlaybookVersion(context.Context, string, string, int, string) (core.SOARPlaybookDetails, error)
	DisableSOARPlaybook(context.Context, string, string, string) (core.SOARPlaybook, error)
	CreateSOARExecution(context.Context, core.SOARExecution, []core.SOARNode) (core.SOARExecution, bool, error)
	GetSOARExecution(context.Context, string, string) (core.SOARExecution, error)
	ListSOARExecutions(context.Context, string, core.SOARExecutionFilter) ([]core.SOARExecution, error)
}

type RuntimeControlStore interface {
	ListSOARApprovals(context.Context, string, core.SOARApprovalFilter) ([]core.SOARApproval, error)
	DecideSOARApproval(context.Context, string, string, string, string, string) (core.SOARApproval, error)
	CompleteSOARManualTask(context.Context, string, string, string, map[string]interface{}) (core.SOARExecution, error)
	ListSOARActionAttempts(context.Context, string, string, int) ([]core.SOARActionAttempt, error)
}

type Service struct {
	store     Store
	validator *Validator
	now       func() time.Time
}

type PlaybookDraft struct {
	Name        string                `json:"name"`
	Description string                `json:"description,omitempty"`
	Spec        core.SOARPlaybookSpec `json:"spec"`
}

type ExecutionRequest struct {
	PlaybookID          string                 `json:"playbook_id"`
	RequestID           string                 `json:"request_id"`
	TriggerType         string                 `json:"trigger_type"`
	TriggerResourceType string                 `json:"trigger_resource_type,omitempty"`
	TriggerResourceID   string                 `json:"trigger_resource_id,omitempty"`
	Context             map[string]interface{} `json:"context,omitempty"`
}

type ApprovalDecisionRequest struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
}

func NewService(store Store, validator *Validator) *Service {
	if validator == nil {
		validator = NewValidator(nil)
	}
	return &Service{store: store, validator: validator, now: func() time.Time { return time.Now().UTC() }}
}

func (s *Service) CreatePlaybook(ctx context.Context, tenantID, actor string, draft PlaybookDraft) (core.SOARPlaybookDetails, error) {
	name := strings.TrimSpace(draft.Name)
	description := strings.TrimSpace(draft.Description)
	if tenantID == "" || actor == "" || len(name) < 2 || len(name) > 160 || len(description) > 4000 {
		return core.SOARPlaybookDetails{}, fmt.Errorf("%w: tenant, actor, and a 2-160 character name are required", ErrInvalidPlaybook)
	}
	report := s.validator.Validate(draft.Spec)
	now := s.now()
	playbook := core.SOARPlaybook{
		ID: core.NewID("pbk"), TenantID: tenantID, Name: name, Description: description,
		State: core.SOARPlaybookDraft, LatestVersion: 1, Revision: 1,
		CreatedBy: actor, UpdatedBy: actor, CreatedAt: now, UpdatedAt: now,
	}
	version := core.SOARPlaybookVersion{
		TenantID: tenantID, PlaybookID: playbook.ID, Version: 1, State: core.SOARVersionDraft,
		Spec: draft.Spec, SpecHash: report.SpecHash, Validation: report, CreatedBy: actor, CreatedAt: now,
	}
	return s.store.CreateSOARPlaybook(ctx, playbook, version)
}

func (s *Service) CreateVersion(ctx context.Context, tenantID, playbookID, actor string, spec core.SOARPlaybookSpec) (core.SOARPlaybookVersion, error) {
	if actor == "" || strings.TrimSpace(playbookID) == "" {
		return core.SOARPlaybookVersion{}, fmt.Errorf("%w: playbook and actor are required", ErrInvalidPlaybook)
	}
	report := s.validator.Validate(spec)
	return s.store.CreateSOARPlaybookVersion(ctx, tenantID, playbookID, actor, spec, report)
}

func (s *Service) ValidateVersion(ctx context.Context, tenantID, playbookID string, version int) (core.SOARPlaybookVersion, error) {
	details, err := s.store.GetSOARPlaybook(ctx, tenantID, playbookID)
	if err != nil {
		return core.SOARPlaybookVersion{}, err
	}
	for _, item := range details.Versions {
		if item.Version == version {
			if item.State == core.SOARVersionPublished || item.State == core.SOARVersionRetired {
				return core.SOARPlaybookVersion{}, fmt.Errorf("%w: immutable published versions cannot be revalidated", ErrInvalidState)
			}
			report := s.validator.Validate(item.Spec)
			return s.store.SaveSOARValidation(ctx, tenantID, playbookID, version, report)
		}
	}
	return core.SOARPlaybookVersion{}, fmt.Errorf("%w: version does not exist", ErrInvalidPlaybook)
}

func (s *Service) PublishVersion(ctx context.Context, tenantID, playbookID string, version int, actor string) (core.SOARPlaybookDetails, error) {
	validated, err := s.ValidateVersion(ctx, tenantID, playbookID, version)
	if err != nil {
		return core.SOARPlaybookDetails{}, err
	}
	if !validated.Validation.Valid {
		return core.SOARPlaybookDetails{}, fmt.Errorf("%w: %d validation issue(s)", ErrValidationFailed, len(validated.Validation.Issues))
	}
	return s.store.PublishSOARPlaybookVersion(ctx, tenantID, playbookID, version, actor)
}

func (s *Service) DisablePlaybook(ctx context.Context, tenantID, playbookID, actor string) (core.SOARPlaybook, error) {
	return s.store.DisableSOARPlaybook(ctx, tenantID, playbookID, actor)
}

func (s *Service) Playbook(ctx context.Context, tenantID, playbookID string) (core.SOARPlaybookDetails, error) {
	return s.store.GetSOARPlaybook(ctx, tenantID, playbookID)
}

func (s *Service) Playbooks(ctx context.Context, tenantID string) ([]core.SOARPlaybook, error) {
	return s.store.ListSOARPlaybooks(ctx, tenantID)
}

func (s *Service) StartExecution(ctx context.Context, tenantID, actor string, request ExecutionRequest) (core.SOARExecution, bool, error) {
	request.PlaybookID = strings.TrimSpace(request.PlaybookID)
	request.RequestID = strings.TrimSpace(request.RequestID)
	request.TriggerType = strings.ToUpper(strings.TrimSpace(request.TriggerType))
	request.TriggerResourceType = strings.TrimSpace(request.TriggerResourceType)
	request.TriggerResourceID = strings.TrimSpace(request.TriggerResourceID)
	if actor == "" || request.PlaybookID == "" || len(request.RequestID) < 8 || len(request.RequestID) > 200 {
		return core.SOARExecution{}, false, fmt.Errorf("%w: actor, playbook, and an 8-200 character request_id are required", ErrInvalidExecution)
	}
	details, err := s.store.GetSOARPlaybook(ctx, tenantID, request.PlaybookID)
	if err != nil {
		return core.SOARExecution{}, false, err
	}
	if details.Playbook.State != core.SOARPlaybookPublished || details.Playbook.PublishedVersion < 1 {
		return core.SOARExecution{}, false, fmt.Errorf("%w: playbook is not published", ErrInvalidState)
	}
	var published core.SOARPlaybookVersion
	for _, version := range details.Versions {
		if version.Version == details.Playbook.PublishedVersion && version.State == core.SOARVersionPublished {
			published = version
			break
		}
	}
	if published.Version == 0 {
		return core.SOARExecution{}, false, fmt.Errorf("%w: published playbook version is unavailable", ErrInvalidState)
	}
	if request.TriggerType != strings.ToUpper(published.Spec.Trigger.Type) {
		return core.SOARExecution{}, false, fmt.Errorf("%w: trigger type does not match the published playbook", ErrInvalidExecution)
	}
	if request.TriggerType != "MANUAL" && (request.TriggerResourceType == "" || request.TriggerResourceID == "") {
		return core.SOARExecution{}, false, fmt.Errorf("%w: alert and incident triggers require a resource identity", ErrInvalidExecution)
	}
	if request.Context == nil {
		request.Context = map[string]interface{}{}
	}
	contextPayload, err := json.Marshal(request.Context)
	if err != nil || len(contextPayload) > 1<<20 {
		return core.SOARExecution{}, false, fmt.Errorf("%w: execution context must be valid JSON smaller than 1 MiB", ErrInvalidExecution)
	}
	now := s.now()
	execution := core.SOARExecution{
		ID: core.NewID("sex"), TenantID: tenantID, PlaybookID: request.PlaybookID,
		PlaybookVersion: published.Version, RequestID: request.RequestID, TriggerType: request.TriggerType,
		TriggerResourceType: request.TriggerResourceType, TriggerResourceID: request.TriggerResourceID,
		Context: request.Context, Status: core.SOARExecutionQueued, Version: 1, TriggeredBy: actor,
		CreatedAt: now, UpdatedAt: now, Nodes: []core.SOARNodeExecution{},
	}
	return s.store.CreateSOARExecution(ctx, execution, published.Spec.Nodes)
}

func (s *Service) Execution(ctx context.Context, tenantID, executionID string) (core.SOARExecution, error) {
	return s.store.GetSOARExecution(ctx, tenantID, executionID)
}

func (s *Service) Executions(ctx context.Context, tenantID string, filter core.SOARExecutionFilter) ([]core.SOARExecution, error) {
	if filter.Limit <= 0 {
		filter.Limit = 100
	}
	if filter.Limit > 500 {
		filter.Limit = 500
	}
	filter.Status = strings.ToUpper(strings.TrimSpace(filter.Status))
	return s.store.ListSOARExecutions(ctx, tenantID, filter)
}

func (s *Service) Approvals(ctx context.Context, tenantID string, filter core.SOARApprovalFilter) ([]core.SOARApproval, error) {
	runtimeStore, err := s.runtimeControlStore()
	if err != nil {
		return nil, err
	}
	filter.Status = strings.ToUpper(strings.TrimSpace(filter.Status))
	switch filter.Status {
	case "", "PENDING", "APPROVED", "REJECTED", "EXPIRED", "CANCELLED":
	default:
		return nil, fmt.Errorf("%w: unsupported approval status", ErrInvalidExecution)
	}
	filter.ExecutionID = strings.TrimSpace(filter.ExecutionID)
	if filter.Limit <= 0 {
		filter.Limit = 100
	}
	if filter.Limit > 500 {
		filter.Limit = 500
	}
	return runtimeStore.ListSOARApprovals(ctx, tenantID, filter)
}

func (s *Service) DecideApproval(ctx context.Context, tenantID, approvalID, actor string,
	request ApprovalDecisionRequest) (core.SOARApproval, error) {
	runtimeStore, err := s.runtimeControlStore()
	if err != nil {
		return core.SOARApproval{}, err
	}
	approvalID = strings.TrimSpace(approvalID)
	actor = strings.TrimSpace(actor)
	request.Decision = strings.ToUpper(strings.TrimSpace(request.Decision))
	request.Reason = strings.TrimSpace(request.Reason)
	if approvalID == "" || actor == "" || (request.Decision != "APPROVE" && request.Decision != "REJECT") ||
		len(request.Reason) < 2 || len(request.Reason) > 2000 {
		return core.SOARApproval{}, fmt.Errorf("%w: approval, actor, APPROVE/REJECT, and a 2-2000 character reason are required", ErrInvalidExecution)
	}
	return runtimeStore.DecideSOARApproval(ctx, tenantID, approvalID, actor, request.Decision, request.Reason)
}

func (s *Service) CompleteManualTask(ctx context.Context, tenantID, executionID, nodeID, actor string,
	output map[string]interface{}) (core.SOARExecution, error) {
	runtimeStore, err := s.runtimeControlStore()
	if err != nil {
		return core.SOARExecution{}, err
	}
	executionID = strings.TrimSpace(executionID)
	nodeID = strings.TrimSpace(nodeID)
	actor = strings.TrimSpace(actor)
	if executionID == "" || nodeID == "" || actor == "" {
		return core.SOARExecution{}, fmt.Errorf("%w: execution, node, and actor are required", ErrInvalidExecution)
	}
	if output == nil {
		output = map[string]interface{}{}
	}
	payload, err := json.Marshal(output)
	if err != nil || len(payload) > 1<<20 {
		return core.SOARExecution{}, fmt.Errorf("%w: manual task output must be valid JSON smaller than 1 MiB", ErrInvalidExecution)
	}
	snapshot := make(map[string]interface{}, len(output)+2)
	for key, value := range output {
		snapshot[key] = value
	}
	snapshot["completed_by"] = actor
	snapshot["completed_at"] = s.now()
	return runtimeStore.CompleteSOARManualTask(ctx, tenantID, executionID, nodeID, snapshot)
}

func (s *Service) ActionAttempts(ctx context.Context, tenantID, executionID string, limit int) ([]core.SOARActionAttempt, error) {
	runtimeStore, err := s.runtimeControlStore()
	if err != nil {
		return nil, err
	}
	executionID = strings.TrimSpace(executionID)
	if executionID == "" {
		return nil, fmt.Errorf("%w: execution_id is required", ErrInvalidExecution)
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	return runtimeStore.ListSOARActionAttempts(ctx, tenantID, executionID, limit)
}

func (s *Service) runtimeControlStore() (RuntimeControlStore, error) {
	runtimeStore, ok := s.store.(RuntimeControlStore)
	if !ok {
		return nil, fmt.Errorf("%w: durable SOAR runtime control is unavailable", ErrInvalidState)
	}
	return runtimeStore, nil
}
