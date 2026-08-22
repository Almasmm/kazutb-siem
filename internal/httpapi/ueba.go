package httpapi

import (
	"net/http"
	"strings"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/ueba"
)

func (s *Server) listUEBAAnomalies(w http.ResponseWriter, r *http.Request) {
	items, err := s.ueba.Anomalies(r.Context(), tenantFrom(r.Context()), core.UEBAAnomalyFilter{
		EntityType:  strings.TrimSpace(r.URL.Query().Get("entity_type")),
		EntityID:    strings.TrimSpace(r.URL.Query().Get("entity_id")),
		Status:      strings.TrimSpace(r.URL.Query().Get("status")),
		MinimumRisk: intQuery(r, "minimum_risk"),
		Limit:       intQuery(r, "limit"),
	})
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, map[string]interface{}{"items": items, "total": len(items)})
}

func (s *Server) getUEBABaseline(w http.ResponseWriter, r *http.Request) {
	item, err := s.ueba.Baseline(r.Context(), tenantFrom(r.Context()), r.PathValue("entityType"), r.PathValue("entityID"))
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, item)
}

func (s *Server) updateUEBAFeedback(w http.ResponseWriter, r *http.Request) {
	var request ueba.FeedbackRequest
	if err := decodeJSON(w, r, &request); err != nil {
		s.handleDecodeError(w, r, "Invalid UEBA feedback", err)
		return
	}
	principal := principalFrom(r.Context())
	item, err := s.ueba.Feedback(r.Context(), tenantFrom(r.Context()), r.PathValue("anomalyID"), principal.ID, request)
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	if _, err := s.store.AppendAudit(r.Context(), core.AuditEntry{
		TenantID: tenantFrom(r.Context()), Actor: principal.ID, Action: "ueba.anomaly.feedback_updated",
		ResourceType: "ueba_anomaly", ResourceID: item.ID, Outcome: "SUCCESS", RequestID: requestIDFrom(r.Context()),
		Metadata: map[string]interface{}{"status": item.Status, "version": item.Version, "model_version": item.ModelVersion},
	}); err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, item)
}
