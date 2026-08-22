package httpapi

import (
	"net/http"
	"strings"

	"github.com/kcsp/platform/internal/aisoc"
	"github.com/kcsp/platform/internal/core"
)

func (s *Server) getAISOCPolicy(w http.ResponseWriter, r *http.Request) {
	policy, err := s.aiSOC.Policy(r.Context(), tenantFrom(r.Context()))
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, policy)
}

func (s *Server) updateAISOCPolicy(w http.ResponseWriter, r *http.Request) {
	var update aisoc.PolicyUpdate
	if err := decodeJSON(w, r, &update); err != nil {
		s.handleDecodeError(w, r, "Invalid AI SOC policy", err)
		return
	}
	principal := principalFrom(r.Context())
	policy, err := s.aiSOC.UpdatePolicy(r.Context(), tenantFrom(r.Context()), principal.ID, update)
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	if _, err := s.store.AppendAudit(r.Context(), core.AuditEntry{
		TenantID: tenantFrom(r.Context()), Actor: principal.ID, Action: "ai.policy.updated",
		ResourceType: "ai_policy", ResourceID: tenantFrom(r.Context()), Outcome: "SUCCESS",
		RequestID: requestIDFrom(r.Context()),
		Metadata: map[string]interface{}{
			"version": policy.Version, "enabled": policy.Enabled, "cloud_allowed": policy.CloudAllowed,
			"pii_redaction": policy.PIIRedaction, "local_model": policy.LocalModel,
			"cloud_model": policy.CloudModel, "action": "policy_only",
		},
	}); err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, policy)
}

func (s *Server) createAISOCRequest(w http.ResponseWriter, r *http.Request) {
	var draft aisoc.RequestDraft
	if err := decodeJSON(w, r, &draft); err != nil {
		s.handleDecodeError(w, r, "Invalid AI SOC request", err)
		return
	}
	if draft.IdempotencyKey == "" {
		draft.IdempotencyKey = strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	}
	principal := principalFrom(r.Context())
	request, created, err := s.aiSOC.Submit(r.Context(), tenantFrom(r.Context()), principal.ID, draft)
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	action := "ai.request.idempotent_replay"
	status := http.StatusOK
	if created {
		action = "ai.request.queued"
		status = http.StatusAccepted
	}
	if _, err := s.store.AppendAudit(r.Context(), core.AuditEntry{
		TenantID: tenantFrom(r.Context()), Actor: principal.ID, Action: action,
		ResourceType: "ai_request", ResourceID: request.ID, Outcome: "SUCCESS",
		RequestID: requestIDFrom(r.Context()),
		Metadata: map[string]interface{}{
			"model": request.Model, "provider": request.Provider, "request_hash": request.RequestHash,
			"context_ids": request.ContextRefs, "user": principal.ID, "decision": "",
			"action": "queue_recommendation",
		},
	}); err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, status, request)
}

func (s *Server) listAISOCRequests(w http.ResponseWriter, r *http.Request) {
	items, err := s.aiSOC.Requests(r.Context(), tenantFrom(r.Context()), core.AISOCRequestFilter{
		Status:      strings.TrimSpace(r.URL.Query().Get("status")),
		Function:    strings.TrimSpace(r.URL.Query().Get("function")),
		Provider:    strings.TrimSpace(r.URL.Query().Get("provider")),
		RequestedBy: strings.TrimSpace(r.URL.Query().Get("requested_by")),
		Limit:       intQuery(r, "limit"),
	})
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, map[string]interface{}{"items": items, "total": len(items)})
}

func (s *Server) getAISOCRequest(w http.ResponseWriter, r *http.Request) {
	details, err := s.aiSOC.Request(r.Context(), tenantFrom(r.Context()), r.PathValue("requestID"))
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, details)
}

func (s *Server) decideAISOCRequest(w http.ResponseWriter, r *http.Request) {
	var draft aisoc.DecisionDraft
	if err := decodeJSON(w, r, &draft); err != nil {
		s.handleDecodeError(w, r, "Invalid AI SOC decision", err)
		return
	}
	principal := principalFrom(r.Context())
	decision, err := s.aiSOC.Decide(r.Context(), tenantFrom(r.Context()), r.PathValue("requestID"), principal.ID, draft)
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	details, err := s.aiSOC.Request(r.Context(), tenantFrom(r.Context()), decision.RequestID)
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	if _, err := s.store.AppendAudit(r.Context(), core.AuditEntry{
		TenantID: tenantFrom(r.Context()), Actor: principal.ID, Action: "ai.recommendation." + strings.ToLower(decision.Decision),
		ResourceType: "ai_request", ResourceID: decision.RequestID, Outcome: "SUCCESS",
		RequestID: requestIDFrom(r.Context()),
		Metadata: map[string]interface{}{
			"model": details.Request.Model, "request_hash": details.Request.RequestHash,
			"context_ids":     details.Request.ContextRefs,
			"response_digest": aisoc.RecommendationDigest(details.Request.Recommendation),
			"user":            principal.ID, "decision": decision.Decision,
			"action": "record_decision_only", "soar_execution_started": false,
		},
	}); err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusCreated, decision)
}
