package httpapi

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/hunt"
)

func (s *Server) searchHunt(w http.ResponseWriter, r *http.Request) {
	var request core.HuntRequest
	if err := decodeJSON(w, r, &request); err != nil {
		s.handleDecodeError(w, r, "Invalid hunt request", err)
		return
	}
	page, err := s.runHunt(r, request, "")
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, page)
}

func (s *Server) listSavedHunts(w http.ResponseWriter, r *http.Request) {
	principal := principalFrom(r.Context())
	items, err := s.hunts.ListSavedHunts(r.Context(), tenantFrom(r.Context()), principal.ID, principal.PlatformScope)
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, map[string]interface{}{"items": items, "total": len(items)})
}

func (s *Server) getSavedHunt(w http.ResponseWriter, r *http.Request) {
	principal := principalFrom(r.Context())
	item, err := s.hunts.SavedHunt(r.Context(), tenantFrom(r.Context()), r.PathValue("huntID"), principal.ID, principal.PlatformScope)
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	w.Header().Set("ETag", fmt.Sprintf("\"%d\"", item.Version))
	s.json(w, http.StatusOK, item)
}

func (s *Server) createSavedHunt(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Name        string           `json:"name"`
		Description string           `json:"description"`
		Visibility  string           `json:"visibility"`
		Query       core.HuntRequest `json:"query"`
	}
	if err := decodeJSON(w, r, &request); err != nil {
		s.handleDecodeError(w, r, "Invalid saved hunt", err)
		return
	}
	template, err := hunt.ValidateTemplate(request.Query, time.Now().UTC())
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	principal := principalFrom(r.Context())
	item, err := s.hunts.CreateSavedHunt(r.Context(), core.SavedHunt{
		TenantID: tenantFrom(r.Context()), Name: request.Name, Description: request.Description,
		Visibility: request.Visibility, Query: template, Owner: principal.ID,
	})
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	if err := s.auditHunt(r, principal.ID, "hunt.saved_created", item.ID, map[string]interface{}{"visibility": item.Visibility}); err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	w.Header().Set("ETag", fmt.Sprintf("\"%d\"", item.Version))
	s.json(w, http.StatusCreated, item)
}

func (s *Server) updateSavedHunt(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Name        string           `json:"name"`
		Description string           `json:"description"`
		Visibility  string           `json:"visibility"`
		Query       core.HuntRequest `json:"query"`
		Version     int              `json:"version"`
	}
	if err := decodeJSON(w, r, &request); err != nil {
		s.handleDecodeError(w, r, "Invalid saved hunt update", err)
		return
	}
	if request.Version == 0 {
		request.Version = ifMatchVersion(r)
	}
	template, err := hunt.ValidateTemplate(request.Query, time.Now().UTC())
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	principal := principalFrom(r.Context())
	item, err := s.hunts.UpdateSavedHunt(r.Context(), core.SavedHunt{
		ID: r.PathValue("huntID"), TenantID: tenantFrom(r.Context()), Name: request.Name,
		Description: request.Description, Visibility: request.Visibility, Query: template, Version: request.Version,
	}, principal.ID, principal.PlatformScope)
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	if err := s.auditHunt(r, principal.ID, "hunt.saved_updated", item.ID, map[string]interface{}{"version": item.Version}); err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	w.Header().Set("ETag", fmt.Sprintf("\"%d\"", item.Version))
	s.json(w, http.StatusOK, item)
}

func (s *Server) deleteSavedHunt(w http.ResponseWriter, r *http.Request) {
	version := intQuery(r, "version")
	if version == 0 {
		version = ifMatchVersion(r)
	}
	principal := principalFrom(r.Context())
	if err := s.hunts.DeleteSavedHunt(r.Context(), tenantFrom(r.Context()), r.PathValue("huntID"), version, principal.ID, principal.PlatformScope); err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	if err := s.auditHunt(r, principal.ID, "hunt.saved_deleted", r.PathValue("huntID"), map[string]interface{}{"version": version}); err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) executeSavedHunt(w http.ResponseWriter, r *http.Request) {
	principal := principalFrom(r.Context())
	item, err := s.hunts.SavedHunt(r.Context(), tenantFrom(r.Context()), r.PathValue("huntID"), principal.ID, principal.PlatformScope)
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	request, err := hunt.ResolveTemplate(item.Query, time.Now().UTC())
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	page, err := s.runHunt(r, request, item.ID)
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, page)
}

func (s *Server) listHuntExecutions(w http.ResponseWriter, r *http.Request) {
	principal := principalFrom(r.Context())
	items, err := s.hunts.ListHuntExecutions(r.Context(), tenantFrom(r.Context()), r.URL.Query().Get("saved_hunt_id"),
		principal.ID, principal.PlatformScope, intQuery(r, "limit"))
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, map[string]interface{}{"items": items, "total": len(items)})
}

func (s *Server) runHunt(r *http.Request, request core.HuntRequest, savedHuntID string) (core.HuntPage, error) {
	normalized, err := hunt.Normalize(request, time.Now().UTC())
	if err != nil {
		return core.HuntPage{}, err
	}
	principal := principalFrom(r.Context())
	tenantID := tenantFrom(r.Context())
	page, searchErr := s.hunts.HuntEvents(r.Context(), tenantID, normalized)
	execution := core.HuntExecution{
		ID: page.ExecutionID, TenantID: tenantID, SavedHuntID: savedHuntID, Actor: principal.ID,
		Query: normalized, QueryHash: hunt.QueryHash(normalized), Status: "SUCCEEDED", Returned: page.Returned,
		DurationMicros: page.DurationMicros, CreatedAt: time.Now().UTC(),
	}
	if searchErr != nil {
		execution.ID = core.NewID("hex")
		execution.Status = "FAILED"
		execution.Error = truncateHuntError(searchErr.Error())
		_ = s.hunts.RecordHuntExecution(r.Context(), execution)
		return core.HuntPage{}, searchErr
	}
	if err := s.hunts.RecordHuntExecution(r.Context(), execution); err != nil {
		return core.HuntPage{}, err
	}
	if err := s.auditHunt(r, principal.ID, "hunt.executed", execution.ID, map[string]interface{}{
		"query_hash": execution.QueryHash, "saved_hunt_id": savedHuntID, "returned": page.Returned,
		"start": normalized.Start, "end": normalized.End, "duration_micros": page.DurationMicros,
	}); err != nil {
		return core.HuntPage{}, err
	}
	return page, nil
}

func (s *Server) auditHunt(r *http.Request, actor, action, resourceID string, metadata map[string]interface{}) error {
	_, err := s.store.AppendAudit(r.Context(), core.AuditEntry{
		TenantID: tenantFrom(r.Context()), Actor: actor, Action: action, ResourceType: "hunt", ResourceID: resourceID,
		Outcome: "SUCCESS", RequestID: requestIDFrom(r.Context()), Metadata: metadata,
	})
	return err
}

func truncateHuntError(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 2000 {
		return value[:2000]
	}
	return value
}
