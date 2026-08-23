package httpapi

import (
	"fmt"
	"net/http"

	"github.com/kcsp/platform/internal/core"
)

func (s *Server) getRetentionPolicy(w http.ResponseWriter, r *http.Request) {
	policy, err := s.retention.RetentionPolicy(r.Context(), tenantFrom(r.Context()))
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	w.Header().Set("ETag", fmt.Sprintf("\"%d\"", policy.Version))
	s.json(w, http.StatusOK, policy)
}

func (s *Server) updateRetentionPolicy(w http.ResponseWriter, r *http.Request) {
	var request struct {
		RawDays        int `json:"raw_days"`
		NormalizedDays int `json:"normalized_days"`
		FindingsDays   int `json:"findings_days"`
		EvidenceDays   int `json:"evidence_days"`
		Version        int `json:"version"`
	}
	if err := decodeJSON(w, r, &request); err != nil {
		s.handleDecodeError(w, r, "Invalid retention policy", err)
		return
	}
	if request.Version == 0 {
		request.Version = ifMatchVersion(r)
	}
	if s.licenses != nil {
		if err := s.licenses.ValidateRetention(
			r.Context(),
			tenantFrom(r.Context()),
			request.RawDays,
			request.NormalizedDays,
			request.FindingsDays,
			request.EvidenceDays,
		); err != nil {
			s.handleLicenseAuthorization(w, r, err)
			return
		}
	}
	principal := principalFrom(r.Context())
	policy, err := s.retention.UpdateRetentionPolicy(r.Context(), core.RetentionPolicy{
		TenantID: tenantFrom(r.Context()), RawDays: request.RawDays, NormalizedDays: request.NormalizedDays,
		FindingsDays: request.FindingsDays, EvidenceDays: request.EvidenceDays, Version: request.Version, UpdatedBy: principal.ID,
	})
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	if _, err := s.store.AppendAudit(r.Context(), core.AuditEntry{
		TenantID: policy.TenantID, Actor: principal.ID, Action: "retention.updated", ResourceType: "retention_policy",
		ResourceID: policy.TenantID, Outcome: "SUCCESS", RequestID: requestIDFrom(r.Context()),
		Metadata: map[string]interface{}{"raw_days": policy.RawDays, "normalized_days": policy.NormalizedDays,
			"findings_days": policy.FindingsDays, "evidence_days": policy.EvidenceDays, "version": policy.Version},
	}); err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	w.Header().Set("ETag", fmt.Sprintf("\"%d\"", policy.Version))
	s.json(w, http.StatusOK, policy)
}
