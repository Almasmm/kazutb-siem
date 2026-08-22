package aisoc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/kcsp/platform/internal/core"
)

var (
	ErrInvalidRequest  = errors.New("invalid AI SOC request")
	ErrInvalidPolicy   = errors.New("invalid AI SOC policy")
	ErrInvalidDecision = errors.New("invalid AI SOC decision")
	ErrPolicyDisabled  = errors.New("AI SOC is disabled by tenant policy")
	ErrCloudDisabled   = errors.New("cloud AI is disabled by tenant policy")
	ErrInvalidOutput   = errors.New("invalid AI SOC structured output")
	ErrContextTooLarge = errors.New("AI SOC context is too large")
)

const RecommendationDisclaimer = "AI-generated recommendation only. Validate against cited KCSP evidence before taking any action."

var safeIdentifier = regexp.MustCompile(`^[A-Za-z0-9._:@/-]{1,200}$`)

type Store interface {
	GetAISOCPolicy(context.Context, string) (core.AISOCPolicy, error)
	UpdateAISOCPolicy(context.Context, core.AISOCPolicy, int) (core.AISOCPolicy, error)
	CreateAISOCRequest(context.Context, core.AISOCRequest) (core.AISOCRequest, bool, error)
	GetAISOCRequest(context.Context, string, string) (core.AISOCRequestDetails, error)
	ListAISOCRequests(context.Context, string, core.AISOCRequestFilter) ([]core.AISOCRequest, error)
	CreateAISOCDecision(context.Context, core.AISOCDecision) (core.AISOCDecision, error)
}

type Service struct {
	store Store
	now   func() time.Time
}

type RequestDraft struct {
	IdempotencyKey string                 `json:"idempotency_key"`
	Function       string                 `json:"function"`
	Question       string                 `json:"question,omitempty"`
	ContextRefs    []core.AISOCContextRef `json:"context_refs"`
	Provider       string                 `json:"provider,omitempty"`
}

type PolicyUpdate struct {
	Version             int     `json:"version"`
	Enabled             *bool   `json:"enabled,omitempty"`
	CloudAllowed        *bool   `json:"cloud_allowed,omitempty"`
	PIIRedaction        *bool   `json:"pii_redaction,omitempty"`
	MaximumContextItems *int    `json:"maximum_context_items,omitempty"`
	LocalModel          *string `json:"local_model,omitempty"`
	CloudModel          *string `json:"cloud_model,omitempty"`
}

type DecisionDraft struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
}

func NewService(store Store) *Service {
	return &Service{store: store, now: func() time.Time { return time.Now().UTC() }}
}

func (s *Service) Policy(ctx context.Context, tenantID string) (core.AISOCPolicy, error) {
	return s.store.GetAISOCPolicy(ctx, tenantID)
}

func (s *Service) UpdatePolicy(ctx context.Context, tenantID, actor string, update PolicyUpdate) (core.AISOCPolicy, error) {
	if update.Version < 1 || strings.TrimSpace(actor) == "" {
		return core.AISOCPolicy{}, ErrInvalidPolicy
	}
	policy, err := s.store.GetAISOCPolicy(ctx, tenantID)
	if err != nil {
		return core.AISOCPolicy{}, err
	}
	if update.Enabled != nil {
		policy.Enabled = *update.Enabled
	}
	if update.CloudAllowed != nil {
		policy.CloudAllowed = *update.CloudAllowed
	}
	if update.PIIRedaction != nil {
		policy.PIIRedaction = *update.PIIRedaction
	}
	if update.MaximumContextItems != nil {
		policy.MaximumContextItems = *update.MaximumContextItems
	}
	if update.LocalModel != nil {
		policy.LocalModel = strings.TrimSpace(*update.LocalModel)
	}
	if update.CloudModel != nil {
		policy.CloudModel = strings.TrimSpace(*update.CloudModel)
	}
	if policy.MaximumContextItems < 1 || policy.MaximumContextItems > 50 ||
		!validModelName(policy.LocalModel) || (policy.CloudAllowed && !validModelName(policy.CloudModel)) {
		return core.AISOCPolicy{}, ErrInvalidPolicy
	}
	policy.UpdatedBy = actor
	policy.UpdatedAt = s.now()
	return s.store.UpdateAISOCPolicy(ctx, policy, update.Version)
}

func (s *Service) Submit(ctx context.Context, tenantID, actor string, draft RequestDraft) (core.AISOCRequest, bool, error) {
	policy, err := s.store.GetAISOCPolicy(ctx, tenantID)
	if err != nil {
		return core.AISOCRequest{}, false, err
	}
	if !policy.Enabled {
		return core.AISOCRequest{}, false, ErrPolicyDisabled
	}
	draft.Function = strings.ToUpper(strings.TrimSpace(draft.Function))
	draft.Provider = strings.ToUpper(strings.TrimSpace(draft.Provider))
	draft.Question = strings.TrimSpace(draft.Question)
	draft.IdempotencyKey = strings.TrimSpace(draft.IdempotencyKey)
	actor = strings.TrimSpace(actor)
	if draft.Provider == "" {
		draft.Provider = core.AISOCProviderLocal
	}
	if !validFunction(draft.Function) || len(draft.Question) > 2000 || actor == "" ||
		len(draft.IdempotencyKey) < 8 || len(draft.IdempotencyKey) > 200 {
		return core.AISOCRequest{}, false, ErrInvalidRequest
	}
	if draft.Provider != core.AISOCProviderLocal && draft.Provider != core.AISOCProviderCloud {
		return core.AISOCRequest{}, false, ErrInvalidRequest
	}
	if draft.Provider == core.AISOCProviderCloud && !policy.CloudAllowed {
		return core.AISOCRequest{}, false, ErrCloudDisabled
	}
	refs, err := normalizeContextRefs(draft.ContextRefs, policy.MaximumContextItems)
	if err != nil {
		return core.AISOCRequest{}, false, err
	}
	if len(refs) == 0 {
		return core.AISOCRequest{}, false, fmt.Errorf("%w: at least one context reference is required", ErrInvalidRequest)
	}
	model := policy.LocalModel
	if draft.Provider == core.AISOCProviderCloud {
		model = policy.CloudModel
	}
	hashInput := struct {
		Function string
		Question string
		Refs     []core.AISOCContextRef
		Provider string
	}{draft.Function, draft.Question, refs, draft.Provider}
	body, _ := json.Marshal(hashInput)
	digest := sha256.Sum256(body)
	now := s.now()
	request := core.AISOCRequest{
		ID: core.NewID("air"), TenantID: tenantID, IdempotencyKey: draft.IdempotencyKey,
		RequestHash: hex.EncodeToString(digest[:]), Function: draft.Function, Question: draft.Question,
		ContextRefs: refs, Status: core.AISOCRequestQueued, Provider: draft.Provider, Model: model,
		RequestedBy: actor, Attempt: 0, Version: 1, CreatedAt: now, UpdatedAt: now,
	}
	return s.store.CreateAISOCRequest(ctx, request)
}

func (s *Service) Request(ctx context.Context, tenantID, requestID string) (core.AISOCRequestDetails, error) {
	return s.store.GetAISOCRequest(ctx, tenantID, strings.TrimSpace(requestID))
}

func (s *Service) Requests(ctx context.Context, tenantID string, filter core.AISOCRequestFilter) ([]core.AISOCRequest, error) {
	filter.Status = strings.ToUpper(strings.TrimSpace(filter.Status))
	filter.Function = strings.ToUpper(strings.TrimSpace(filter.Function))
	filter.Provider = strings.ToUpper(strings.TrimSpace(filter.Provider))
	filter.RequestedBy = strings.TrimSpace(filter.RequestedBy)
	if filter.Status != "" && !validStatus(filter.Status) {
		return nil, ErrInvalidRequest
	}
	if filter.Function != "" && !validFunction(filter.Function) {
		return nil, ErrInvalidRequest
	}
	if filter.Provider != "" && filter.Provider != core.AISOCProviderLocal && filter.Provider != core.AISOCProviderCloud {
		return nil, ErrInvalidRequest
	}
	if filter.Limit < 0 || filter.Limit > 1000 {
		return nil, ErrInvalidRequest
	}
	return s.store.ListAISOCRequests(ctx, tenantID, filter)
}

func (s *Service) Decide(ctx context.Context, tenantID, requestID, actor string, draft DecisionDraft) (core.AISOCDecision, error) {
	draft.Decision = strings.ToUpper(strings.TrimSpace(draft.Decision))
	draft.Reason = strings.TrimSpace(draft.Reason)
	actor = strings.TrimSpace(actor)
	if draft.Decision != core.AISOCDecisionAccepted && draft.Decision != core.AISOCDecisionRejected {
		return core.AISOCDecision{}, ErrInvalidDecision
	}
	if actor == "" || len(draft.Reason) < 2 || len(draft.Reason) > 2000 {
		return core.AISOCDecision{}, ErrInvalidDecision
	}
	details, err := s.store.GetAISOCRequest(ctx, tenantID, requestID)
	if err != nil {
		return core.AISOCDecision{}, err
	}
	if details.Request.Status != core.AISOCRequestSucceeded || details.Decision != nil {
		return core.AISOCDecision{}, ErrInvalidDecision
	}
	return s.store.CreateAISOCDecision(ctx, core.AISOCDecision{
		ID: core.NewID("aid"), TenantID: tenantID, RequestID: requestID,
		Decision: draft.Decision, Reason: draft.Reason, DecidedBy: actor, CreatedAt: s.now(),
	})
}

func RecommendationDigest(recommendation core.AISOCRecommendation) string {
	body, _ := json.Marshal(recommendation)
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func normalizeContextRefs(input []core.AISOCContextRef, maximum int) ([]core.AISOCContextRef, error) {
	if maximum < 1 {
		maximum = 20
	}
	if len(input) > maximum {
		return nil, fmt.Errorf("%w: maximum context items exceeded", ErrInvalidRequest)
	}
	result := make([]core.AISOCContextRef, 0, len(input))
	seen := map[string]bool{}
	for _, ref := range input {
		ref.Type = strings.ToLower(strings.TrimSpace(ref.Type))
		ref.ID = strings.TrimSpace(ref.ID)
		if (ref.Type != "event" && ref.Type != "alert" && ref.Type != "incident") || !safeIdentifier.MatchString(ref.ID) {
			return nil, ErrInvalidRequest
		}
		key := ref.Type + ":" + ref.ID
		if !seen[key] {
			result = append(result, ref)
			seen[key] = true
		}
	}
	return result, nil
}

func validModelName(value string) bool {
	value = strings.TrimSpace(value)
	return len(value) >= 2 && len(value) <= 160 && !strings.ContainsAny(value, "\r\n")
}

func validFunction(value string) bool {
	switch value {
	case core.AISOCIncidentSummary, core.AISOCEventExplanation, core.AISOCInvestigationSteps,
		core.AISOCCQLGeneration, core.AISOCSigmaDraft, core.AISOCParserDraft,
		core.AISOCMITRESuggestion, core.AISOCEvidenceTimeline, core.AISOCCaseClosureReport,
		core.AISOCExecutiveReport:
		return true
	default:
		return false
	}
}

func validStatus(value string) bool {
	switch value {
	case core.AISOCRequestQueued, core.AISOCRequestRunning, core.AISOCRequestSucceeded,
		core.AISOCRequestFailed, core.AISOCRequestBlocked:
		return true
	default:
		return false
	}
}
