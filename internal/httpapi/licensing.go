package httpapi

import (
	"errors"
	"net/http"
	"strings"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/licensing"
)

func (s *Server) currentLicense(w http.ResponseWriter, r *http.Request) {
	status, err := s.licenses.Status(r.Context(), tenantFrom(r.Context()))
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, status)
}

func (s *Server) listLicenses(w http.ResponseWriter, r *http.Request) {
	items, err := s.licenses.Licenses(r.Context(), tenantFrom(r.Context()))
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, map[string]interface{}{"items": items, "total": len(items)})
}

func (s *Server) installLicense(w http.ResponseWriter, r *http.Request) {
	var input licensing.InstallInput
	if err := decodeJSON(w, r, &input); err != nil {
		s.handleDecodeError(w, r, "Invalid license package", err)
		return
	}
	if requestID := strings.TrimSpace(r.Header.Get("Idempotency-Key")); requestID != "" {
		input.RequestID = requestID
	}
	principal := principalFrom(r.Context())
	record, created, err := s.licenses.Install(r.Context(), tenantFrom(r.Context()), principal.ID, input)
	if err != nil {
		s.handleLicenseError(w, r, err)
		return
	}
	action := "license.installation_replayed"
	statusCode := http.StatusOK
	if created {
		action = "license.installed"
		statusCode = http.StatusCreated
	}
	if _, err = s.store.AppendAudit(r.Context(), core.AuditEntry{
		TenantID: record.TenantID, Actor: principal.ID, Action: action, ResourceType: "license", ResourceID: record.LicenseID,
		Outcome: "SUCCESS", RequestID: requestIDFrom(r.Context()),
		Metadata: map[string]interface{}{"key_id": record.KeyID, "fingerprint_sha256": record.Fingerprint, "expires_at": record.Payload.ExpiresAt, "modules": record.Payload.Modules},
	}); err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, statusCode, record)
}

func (s *Server) listAdminTenants(w http.ResponseWriter, r *http.Request) {
	if !s.requirePlatformScope(w, r) {
		return
	}
	items, total, err := s.licenses.Tenants(r.Context(), core.TenantFilter{Query: r.URL.Query().Get("q"), Limit: intQuery(r, "limit"), Offset: intQuery(r, "offset")})
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, map[string]interface{}{"items": items, "total": total})
}

func (s *Server) createAdminTenant(w http.ResponseWriter, r *http.Request) {
	if !s.requirePlatformScope(w, r) {
		return
	}
	var input licensing.TenantInput
	if err := decodeJSON(w, r, &input); err != nil {
		s.handleDecodeError(w, r, "Invalid tenant", err)
		return
	}
	principal := principalFrom(r.Context())
	item, err := s.licenses.CreateTenant(r.Context(), tenantFrom(r.Context()), input)
	if err != nil {
		s.handleLicenseError(w, r, err)
		return
	}
	if _, err = s.store.AppendAudit(r.Context(), core.AuditEntry{
		TenantID: item.ID, Actor: principal.ID, Action: "tenant.created", ResourceType: "tenant", ResourceID: item.ID,
		Outcome: "SUCCESS", RequestID: requestIDFrom(r.Context()), Metadata: map[string]interface{}{"display_name": item.DisplayName, "state": item.State},
	}); err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusCreated, item)
}

func (s *Server) updateAdminTenant(w http.ResponseWriter, r *http.Request) {
	if !s.requirePlatformScope(w, r) {
		return
	}
	var input struct {
		State string `json:"state"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		s.handleDecodeError(w, r, "Invalid tenant state", err)
		return
	}
	item, err := s.licenses.SetTenantState(r.Context(), r.PathValue("tenantID"), input.State)
	if err != nil {
		s.handleLicenseError(w, r, err)
		return
	}
	principal := principalFrom(r.Context())
	if _, err = s.store.AppendAudit(r.Context(), core.AuditEntry{
		TenantID: item.ID, Actor: principal.ID, Action: "tenant.state_changed", ResourceType: "tenant", ResourceID: item.ID,
		Outcome: "SUCCESS", RequestID: requestIDFrom(r.Context()), Metadata: map[string]interface{}{"state": item.State},
	}); err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, item)
}

func (s *Server) requirePlatformScope(w http.ResponseWriter, r *http.Request) bool {
	if principalFrom(r.Context()).PlatformScope {
		return true
	}
	s.problem(w, r, http.StatusForbidden, "platform_scope_required", "Platform scope required", "Cross-tenant administration requires an explicitly scoped platform principal.")
	return false
}

func (s *Server) handleLicenseError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, licensing.ErrInvalidLicense), errors.Is(err, licensing.ErrUntrustedKey):
		s.problem(w, r, http.StatusBadRequest, "invalid_license", "Invalid license", err.Error())
	case errors.Is(err, licensing.ErrTenantLimitExceeded):
		s.problem(w, r, http.StatusConflict, "tenant_limit_exceeded", "Tenant limit exceeded", err.Error())
	default:
		s.handleDomainError(w, r, err)
	}
}
