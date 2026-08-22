package httpapi

import (
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/evidence"
)

func (s *Server) uploadEvidence(w http.ResponseWriter, r *http.Request) {
	principal := principalFrom(r.Context())
	item, duplicate, err := s.evidence.Upload(r.Context(), evidence.UploadInput{
		TenantID: tenantFrom(r.Context()), RequestID: requestIDFrom(r.Context()), Actor: principal.ID,
		Filename: r.Header.Get("X-KCSP-Filename"), ContentType: r.Header.Get("Content-Type"),
		Description: r.Header.Get("X-KCSP-Description"), IncidentID: r.Header.Get("X-KCSP-Incident-ID"),
		AlertID: r.Header.Get("X-KCSP-Alert-ID"), EventID: r.Header.Get("X-KCSP-Event-ID"),
		ExpectedSHA256: r.Header.Get("X-KCSP-SHA256"), Reader: r.Body,
	})
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	if _, err := s.store.AppendAudit(r.Context(), core.AuditEntry{
		TenantID: item.TenantID, Actor: principal.ID, Action: "evidence.uploaded", ResourceType: "evidence",
		ResourceID: item.ID, Outcome: "SUCCESS", RequestID: requestIDFrom(r.Context()),
		Metadata: map[string]interface{}{"sha256": item.SHA256, "size": item.Size, "duplicate": duplicate},
	}); err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	status := http.StatusCreated
	if duplicate {
		status = http.StatusOK
	}
	s.json(w, status, item)
}

func (s *Server) listEvidence(w http.ResponseWriter, r *http.Request) {
	items, err := s.evidence.List(r.Context(), tenantFrom(r.Context()), core.EvidenceFilter{
		IncidentID: r.URL.Query().Get("incident_id"), AlertID: r.URL.Query().Get("alert_id"),
		EventID: r.URL.Query().Get("event_id"), Status: r.URL.Query().Get("status"), Limit: intQuery(r, "limit"),
	})
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, map[string]interface{}{"items": items, "total": len(items)})
}

func (s *Server) getEvidence(w http.ResponseWriter, r *http.Request) {
	item, err := s.evidence.Evidence(r.Context(), tenantFrom(r.Context()), r.PathValue("evidenceID"))
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, item)
}

func (s *Server) downloadEvidence(w http.ResponseWriter, r *http.Request) {
	principal := principalFrom(r.Context())
	reason := strings.TrimSpace(r.Header.Get("X-KCSP-Access-Reason"))
	reader, item, err := s.evidence.Open(r.Context(), tenantFrom(r.Context()), r.PathValue("evidenceID"), principal.ID, reason, requestIDFrom(r.Context()))
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	defer reader.Close()
	if _, err := s.store.AppendAudit(r.Context(), core.AuditEntry{
		TenantID: item.TenantID, Actor: principal.ID, Action: "evidence.downloaded", ResourceType: "evidence",
		ResourceID: item.ID, Outcome: "SUCCESS", RequestID: requestIDFrom(r.Context()), Metadata: map[string]interface{}{"reason": reason},
	}); err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", item.ContentType)
	w.Header().Set("Content-Length", strconv.FormatInt(item.Size, 10))
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": item.Filename}))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-KCSP-SHA256", item.SHA256)
	if item.ETag != "" {
		w.Header().Set("ETag", `"`+item.ETag+`"`)
	}
	w.WriteHeader(http.StatusOK)
	if _, err := io.Copy(w, reader); err != nil {
		s.logger.Error("evidence stream failed", "error", err, "evidence_id", item.ID, "request_id", requestIDFrom(r.Context()))
	}
}

func (s *Server) verifyEvidence(w http.ResponseWriter, r *http.Request) {
	principal := principalFrom(r.Context())
	reason := strings.TrimSpace(r.Header.Get("X-KCSP-Access-Reason"))
	report, err := s.evidence.Verify(r.Context(), tenantFrom(r.Context()), r.PathValue("evidenceID"), principal.ID, reason, requestIDFrom(r.Context()))
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	if _, err := s.store.AppendAudit(r.Context(), core.AuditEntry{
		TenantID: tenantFrom(r.Context()), Actor: principal.ID, Action: "evidence.verified", ResourceType: "evidence",
		ResourceID: report.EvidenceID, Outcome: "SUCCESS", RequestID: requestIDFrom(r.Context()),
		Metadata: map[string]interface{}{"valid": report.Valid, "sha256": report.Actual, "reason": reason},
	}); err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, report)
}

func (s *Server) listEvidenceCustody(w http.ResponseWriter, r *http.Request) {
	items, valid, err := s.evidence.Custody(r.Context(), tenantFrom(r.Context()), r.PathValue("evidenceID"))
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, map[string]interface{}{"items": items, "total": len(items), "chain_valid": valid})
}
