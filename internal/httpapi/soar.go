package httpapi

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/soar"
)

func (s *Server) listSOARPlaybooks(w http.ResponseWriter, r *http.Request) {
	items, err := s.soar.Playbooks(r.Context(), tenantFrom(r.Context()))
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, map[string]interface{}{"items": items, "total": len(items)})
}

func (s *Server) createSOARPlaybook(w http.ResponseWriter, r *http.Request) {
	var draft soar.PlaybookDraft
	if err := decodeJSON(w, r, &draft); err != nil {
		s.handleDecodeError(w, r, "Invalid SOAR playbook", err)
		return
	}
	principal := principalFrom(r.Context())
	details, err := s.soar.CreatePlaybook(r.Context(), tenantFrom(r.Context()), principal.ID, draft)
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	if err := s.auditSOAR(r, principal.ID, "soar.playbook.created", "soar_playbook", details.Playbook.ID,
		map[string]interface{}{"version": 1, "valid": details.Versions[0].Validation.Valid}); err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusCreated, details)
}

func (s *Server) getSOARPlaybook(w http.ResponseWriter, r *http.Request) {
	details, err := s.soar.Playbook(r.Context(), tenantFrom(r.Context()), r.PathValue("playbookID"))
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, details)
}

func (s *Server) createSOARVersion(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Spec core.SOARPlaybookSpec `json:"spec"`
	}
	if err := decodeJSON(w, r, &request); err != nil {
		s.handleDecodeError(w, r, "Invalid SOAR playbook version", err)
		return
	}
	principal := principalFrom(r.Context())
	version, err := s.soar.CreateVersion(r.Context(), tenantFrom(r.Context()), r.PathValue("playbookID"), principal.ID, request.Spec)
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	if err := s.auditSOAR(r, principal.ID, "soar.playbook.version_created", "soar_playbook", version.PlaybookID,
		map[string]interface{}{"version": version.Version, "valid": version.Validation.Valid}); err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusCreated, version)
}

func (s *Server) validateSOARVersion(w http.ResponseWriter, r *http.Request) {
	versionNumber, err := soarVersionPath(r)
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	version, err := s.soar.ValidateVersion(r.Context(), tenantFrom(r.Context()), r.PathValue("playbookID"), versionNumber)
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	principal := principalFrom(r.Context())
	if err := s.auditSOAR(r, principal.ID, "soar.playbook.validated", "soar_playbook", version.PlaybookID,
		map[string]interface{}{"version": version.Version, "valid": version.Validation.Valid,
			"issues": len(version.Validation.Issues), "spec_hash": version.SpecHash}); err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, version)
}

func (s *Server) publishSOARVersion(w http.ResponseWriter, r *http.Request) {
	versionNumber, err := soarVersionPath(r)
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	principal := principalFrom(r.Context())
	details, err := s.soar.PublishVersion(r.Context(), tenantFrom(r.Context()), r.PathValue("playbookID"), versionNumber, principal.ID)
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	if err := s.auditSOAR(r, principal.ID, "soar.playbook.published", "soar_playbook", details.Playbook.ID,
		map[string]interface{}{"version": versionNumber}); err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, details)
}

func (s *Server) disableSOARPlaybook(w http.ResponseWriter, r *http.Request) {
	principal := principalFrom(r.Context())
	playbook, err := s.soar.DisablePlaybook(r.Context(), tenantFrom(r.Context()), r.PathValue("playbookID"), principal.ID)
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	if err := s.auditSOAR(r, principal.ID, "soar.playbook.disabled", "soar_playbook", playbook.ID,
		map[string]interface{}{"revision": playbook.Revision}); err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, playbook)
}

func (s *Server) listSOARExecutions(w http.ResponseWriter, r *http.Request) {
	items, err := s.soar.Executions(r.Context(), tenantFrom(r.Context()), core.SOARExecutionFilter{
		PlaybookID: strings.TrimSpace(r.URL.Query().Get("playbook_id")),
		Status:     strings.TrimSpace(r.URL.Query().Get("status")),
		Limit:      intQuery(r, "limit"),
	})
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, map[string]interface{}{"items": items, "total": len(items)})
}

func (s *Server) startSOARExecution(w http.ResponseWriter, r *http.Request) {
	var request soar.ExecutionRequest
	if err := decodeJSON(w, r, &request); err != nil {
		s.handleDecodeError(w, r, "Invalid SOAR execution", err)
		return
	}
	principal := principalFrom(r.Context())
	execution, created, err := s.soar.StartExecution(r.Context(), tenantFrom(r.Context()), principal.ID, request)
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	action := "soar.execution.idempotent_replay"
	status := http.StatusOK
	if created {
		action = "soar.execution.queued"
		status = http.StatusAccepted
	}
	if err := s.auditSOAR(r, principal.ID, action, "soar_execution", execution.ID,
		map[string]interface{}{"playbook_id": execution.PlaybookID, "playbook_version": execution.PlaybookVersion,
			"trigger_type": execution.TriggerType, "request_id": execution.RequestID}); err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, status, execution)
}

func (s *Server) getSOARExecution(w http.ResponseWriter, r *http.Request) {
	execution, err := s.soar.Execution(r.Context(), tenantFrom(r.Context()), r.PathValue("executionID"))
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, execution)
}

func (s *Server) auditSOAR(r *http.Request, actor, action, resourceType, resourceID string, metadata map[string]interface{}) error {
	_, err := s.store.AppendAudit(r.Context(), core.AuditEntry{
		TenantID: tenantFrom(r.Context()), Actor: actor, Action: action, ResourceType: resourceType,
		ResourceID: resourceID, Outcome: "SUCCESS", RequestID: requestIDFrom(r.Context()), Metadata: metadata,
	})
	return err
}

func soarVersionPath(r *http.Request) (int, error) {
	value, err := strconv.Atoi(r.PathValue("version"))
	if err != nil || value < 1 {
		return 0, soar.ErrInvalidPlaybook
	}
	return value, nil
}
