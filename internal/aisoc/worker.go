package aisoc

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/kcsp/platform/internal/core"
)

type RuntimeStore interface {
	ContextStore
	GetAISOCPolicy(context.Context, string) (core.AISOCPolicy, error)
	ClaimAISOCRequest(context.Context, string, string, time.Duration) (core.AISOCRequest, bool, error)
	CompleteAISOCRequest(context.Context, core.AISOCRequest, string) (core.AISOCRequest, error)
	FinishAISOCRequestFailure(context.Context, string, string, string, string, string, string, []core.AISOCContextDocument, string, int, bool) (core.AISOCRequest, error)
	AppendAudit(context.Context, core.AuditEntry) (core.AuditEntry, error)
}

type WorkerConfig struct {
	ID           string
	TenantID     string
	PollInterval time.Duration
	Lease        time.Duration
}

type Worker struct {
	store  RuntimeStore
	local  Gateway
	cloud  Gateway
	config WorkerConfig
	logger *slog.Logger
}

func NewWorker(store RuntimeStore, local, cloud Gateway, config WorkerConfig, logger *slog.Logger) *Worker {
	if local == nil {
		local = NewGroundedGateway("kcsp-grounded-rules-v1")
	}
	if strings.TrimSpace(config.ID) == "" {
		config.ID = "ai-worker"
	}
	if config.PollInterval <= 0 {
		config.PollInterval = 500 * time.Millisecond
	}
	if config.Lease <= 0 {
		config.Lease = 90 * time.Second
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Worker{store: store, local: local, cloud: cloud, config: config, logger: logger}
}

func (w *Worker) Run(ctx context.Context) error {
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
			worked, err := w.ProcessOne(ctx)
			if err != nil {
				w.logger.Error("AI SOC work item failed", "error", err)
			}
			delay := w.config.PollInterval
			if worked {
				delay = 10 * time.Millisecond
			}
			timer.Reset(delay)
		}
	}
}

func (w *Worker) ProcessOne(ctx context.Context) (bool, error) {
	request, found, err := w.store.ClaimAISOCRequest(ctx, w.config.ID, w.config.TenantID, w.config.Lease)
	if err != nil || !found {
		return found, err
	}
	policy, err := w.store.GetAISOCPolicy(ctx, request.TenantID)
	if err != nil {
		return true, w.fail(ctx, request, core.AISOCRequestFailed, "POLICY_UNAVAILABLE",
			"Tenant AI policy could not be loaded.", nil, "", 0, false)
	}
	if !policy.Enabled {
		return true, w.fail(ctx, request, core.AISOCRequestBlocked, "POLICY_DISABLED",
			"AI SOC is disabled by tenant policy.", nil, "", 0, false)
	}
	if request.Provider == core.AISOCProviderCloud && !policy.CloudAllowed {
		return true, w.fail(ctx, request, core.AISOCRequestBlocked, "CLOUD_DISABLED",
			"Cloud AI is disabled by tenant policy.", nil, "", 0, false)
	}
	documents, digest, redactions, injectionDetected, err := BuildContext(ctx, w.store, policy, request)
	if err != nil {
		return true, w.fail(ctx, request, core.AISOCRequestFailed, "CONTEXT_BUILD_FAILED",
			"Tenant-scoped context could not be built.", nil, "", 0, false)
	}
	if injectionDetected {
		return true, w.fail(ctx, request, core.AISOCRequestBlocked, "PROMPT_INJECTION_BLOCKED",
			"Untrusted context contained instruction-like content and was blocked for analyst review.",
			documents, digest, redactions, true)
	}
	request.ContextDocuments = documents
	request.ContextDigest = digest
	request.RedactionCount = redactions
	gateway := w.local
	if request.Provider == core.AISOCProviderCloud {
		gateway = w.cloud
	}
	if gateway == nil {
		return true, w.fail(ctx, request, core.AISOCRequestFailed, "GATEWAY_UNAVAILABLE",
			"The approved AI gateway is not configured.", documents, digest, redactions, false)
	}
	recommendation, model, err := gateway.Generate(ctx, GenerationInput{Policy: policy, Request: request, Documents: documents})
	if err != nil {
		return true, w.fail(ctx, request, core.AISOCRequestFailed, "GATEWAY_FAILED",
			"The AI gateway did not produce a recommendation.", documents, digest, redactions, false)
	}
	if strings.TrimSpace(model) != strings.TrimSpace(request.Model) {
		return true, w.fail(ctx, request, core.AISOCRequestFailed, "MODEL_POLICY_MISMATCH",
			"The AI gateway returned a model that is not approved by tenant policy.",
			documents, digest, redactions, false)
	}
	recommendation, err = ValidateRecommendation(request, recommendation)
	if err != nil {
		return true, w.fail(ctx, request, core.AISOCRequestFailed, "OUTPUT_POLICY_REJECTED",
			"The AI output failed structured policy validation.", documents, digest, redactions, false)
	}
	request.Model = model
	request.Recommendation = recommendation
	completed, err := w.store.CompleteAISOCRequest(ctx, request, w.config.ID)
	if err != nil {
		return true, err
	}
	_, err = w.store.AppendAudit(ctx, core.AuditEntry{
		TenantID: request.TenantID, Actor: "system:ai-worker", Action: "ai.recommendation.generated",
		ResourceType: "ai_request", ResourceID: request.ID, Outcome: "SUCCESS",
		Metadata: map[string]interface{}{
			"model": model, "provider": request.Provider, "request_hash": request.RequestHash,
			"context_ids": request.ContextRefs, "context_digest": digest,
			"response_digest": RecommendationDigest(recommendation), "requested_by": request.RequestedBy,
			"decision": "", "action": "recommendation_only", "redaction_count": redactions,
		},
	})
	if err != nil {
		return true, fmt.Errorf("audit AI recommendation: %w", err)
	}
	w.logger.Info("AI SOC recommendation completed", "tenant_id", completed.TenantID,
		"request_id", completed.ID, "model", model)
	return true, nil
}

func (w *Worker) fail(ctx context.Context, request core.AISOCRequest, status, class, detail string,
	documents []core.AISOCContextDocument, digest string, redactions int, injectionDetected bool) error {
	failed, err := w.store.FinishAISOCRequestFailure(ctx, request.TenantID, request.ID, w.config.ID,
		status, class, detail, documents, digest, redactions, injectionDetected)
	if err != nil {
		return err
	}
	_, err = w.store.AppendAudit(ctx, core.AuditEntry{
		TenantID: request.TenantID, Actor: "system:ai-worker", Action: "ai.request." + strings.ToLower(status),
		ResourceType: "ai_request", ResourceID: request.ID, Outcome: status,
		Metadata: map[string]interface{}{
			"model": request.Model, "provider": request.Provider, "request_hash": request.RequestHash,
			"context_ids": request.ContextRefs, "context_digest": digest, "requested_by": request.RequestedBy,
			"decision": "", "action": "none", "failure_class": class,
			"prompt_injection_detected": injectionDetected, "redaction_count": redactions,
		},
	})
	if err != nil {
		return fmt.Errorf("audit AI failure %s: %w", failed.ID, err)
	}
	return nil
}
