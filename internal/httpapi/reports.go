package httpapi

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/reporting"
)

func (s *Server) listReports(w http.ResponseWriter, r *http.Request) {
	items, err := s.reports.Reports(r.Context(), tenantFrom(r.Context()), core.ReportFilter{
		Type: r.URL.Query().Get("type"), Status: r.URL.Query().Get("status"), Limit: intQuery(r, "limit"),
	})
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, map[string]interface{}{"items": items, "total": len(items)})
}

func (s *Server) generateReport(w http.ResponseWriter, r *http.Request) {
	var input reporting.GenerateInput
	if err := decodeJSON(w, r, &input); err != nil {
		s.handleDecodeError(w, r, "Invalid report request", err)
		return
	}
	if requestID := strings.TrimSpace(r.Header.Get("Idempotency-Key")); requestID != "" {
		input.RequestID = requestID
	}
	principal := principalFrom(r.Context())
	run, created, err := s.reports.Generate(r.Context(), tenantFrom(r.Context()), principal.ID, input)
	if err != nil {
		s.handleReportError(w, r, err)
		return
	}
	action := "report.reused"
	if created {
		action = "report.generated"
	}
	if _, err = s.store.AppendAudit(r.Context(), core.AuditEntry{
		TenantID: run.TenantID, Actor: principal.ID, Action: action, ResourceType: "report", ResourceID: run.ID,
		Outcome: "SUCCESS", RequestID: requestIDFrom(r.Context()),
		Metadata: map[string]interface{}{"report_type": run.Type, "checksum_sha256": run.Checksum, "created": created},
	}); err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	s.json(w, status, run)
}

func (s *Server) getReport(w http.ResponseWriter, r *http.Request) {
	run, err := s.reports.Report(r.Context(), tenantFrom(r.Context()), r.PathValue("reportID"))
	if err != nil {
		s.handleReportError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, run)
}

func (s *Server) downloadReport(w http.ResponseWriter, r *http.Request) {
	run, err := s.reports.Report(r.Context(), tenantFrom(r.Context()), r.PathValue("reportID"))
	if err != nil {
		s.handleReportError(w, r, err)
		return
	}
	payload, contentType, filename, err := s.reports.Render(run, r.URL.Query().Get("format"))
	if err != nil {
		s.handleReportError(w, r, err)
		return
	}
	principal := principalFrom(r.Context())
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "" {
		format = "json"
	}
	if _, err = s.store.AppendAudit(r.Context(), core.AuditEntry{
		TenantID: run.TenantID, Actor: principal.ID, Action: "report.downloaded", ResourceType: "report", ResourceID: run.ID,
		Outcome: "SUCCESS", RequestID: requestIDFrom(r.Context()),
		Metadata: map[string]interface{}{"report_type": run.Type, "format": format, "checksum_sha256": run.Checksum},
	}); err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("X-KCSP-Report-SHA256", run.Checksum)
	w.Header().Set("X-KCSP-Content-SHA256", run.Checksum)
	w.Header().Set("X-KCSP-SHA256", run.Checksum)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(payload)
}

func (s *Server) handleReportError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, reporting.ErrInvalidReport) {
		s.problem(w, r, http.StatusBadRequest, "invalid_report", "Invalid report", err.Error())
		return
	}
	s.handleDomainError(w, r, err)
}
