package httpapi

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/kcsp/platform/internal/cases"
	"github.com/kcsp/platform/internal/core"
)

func (s *Server) listCases(w http.ResponseWriter, r *http.Request) {
	items, err := s.cases.Cases(r.Context(), tenantFrom(r.Context()), core.CaseFilter{Query: r.URL.Query().Get("q"), Status: r.URL.Query().Get("status"), Severity: r.URL.Query().Get("severity"), Owner: r.URL.Query().Get("owner"), IncidentID: r.URL.Query().Get("incident_id"), Limit: intQuery(r, "limit")})
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, map[string]interface{}{"items": items, "total": len(items)})
}

func (s *Server) createCase(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Title        string                   `json:"title"`
		Description  string                   `json:"description"`
		Severity     core.Severity            `json:"severity"`
		Owner        string                   `json:"owner"`
		IncidentIDs  []string                 `json:"incident_ids"`
		Participants []cases.ParticipantInput `json:"participants"`
		Observables  []cases.ObservableInput  `json:"observables"`
	}
	if err := decodeJSON(w, r, &request); err != nil {
		s.handleDecodeError(w, r, "Invalid case", err)
		return
	}
	requestID := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if requestID == "" {
		requestID = requestIDFrom(r.Context())
	}
	principal := principalFrom(r.Context())
	item, duplicate, err := s.cases.Create(r.Context(), tenantFrom(r.Context()), principal.ID, cases.CreateInput{Title: request.Title, Description: request.Description, Severity: request.Severity, Owner: request.Owner, IncidentIDs: request.IncidentIDs, Participants: request.Participants, Observables: request.Observables, RequestID: requestID})
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	status := http.StatusCreated
	if duplicate {
		status = http.StatusOK
	}
	w.Header().Set("ETag", fmt.Sprintf("\"%d\"", item.Version))
	s.json(w, status, item)
}

func (s *Server) getCase(w http.ResponseWriter, r *http.Request) {
	item, err := s.cases.Case(r.Context(), tenantFrom(r.Context()), r.PathValue("caseID"))
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	w.Header().Set("ETag", fmt.Sprintf("\"%d\"", item.Version))
	s.json(w, http.StatusOK, item)
}

func (s *Server) updateCase(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Title          string        `json:"title"`
		Description    *string       `json:"description"`
		Status         string        `json:"status"`
		Severity       core.Severity `json:"severity"`
		Owner          string        `json:"owner"`
		ClosureSummary string        `json:"closure_summary"`
		Version        int           `json:"version"`
	}
	if err := decodeJSON(w, r, &request); err != nil {
		s.handleDecodeError(w, r, "Invalid case update", err)
		return
	}
	if request.Version == 0 {
		request.Version = ifMatchVersion(r)
	}
	principal := principalFrom(r.Context())
	item, err := s.cases.Update(r.Context(), tenantFrom(r.Context()), r.PathValue("caseID"), principal.ID, cases.Patch{Title: request.Title, Description: request.Description, Status: request.Status, Severity: request.Severity, Owner: request.Owner, ClosureSummary: request.ClosureSummary, Version: request.Version, RequestID: requestIDFrom(r.Context())})
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	w.Header().Set("ETag", fmt.Sprintf("\"%d\"", item.Version))
	s.json(w, http.StatusOK, item)
}

func (s *Server) addCaseComment(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Body    string `json:"body"`
		Version int    `json:"version"`
	}
	if err := decodeJSON(w, r, &request); err != nil {
		s.handleDecodeError(w, r, "Invalid case comment", err)
		return
	}
	if request.Version == 0 {
		request.Version = ifMatchVersion(r)
	}
	principal := principalFrom(r.Context())
	item, err := s.cases.AddComment(r.Context(), tenantFrom(r.Context()), r.PathValue("caseID"), principal.ID, request.Body, requestIDFrom(r.Context()), request.Version)
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusCreated, item)
}

func (s *Server) addCaseTask(w http.ResponseWriter, r *http.Request) {
	var request cases.TaskInput
	if err := decodeJSON(w, r, &request); err != nil {
		s.handleDecodeError(w, r, "Invalid case task", err)
		return
	}
	if request.Version == 0 {
		request.Version = ifMatchVersion(r)
	}
	principal := principalFrom(r.Context())
	item, err := s.cases.AddTask(r.Context(), tenantFrom(r.Context()), r.PathValue("caseID"), principal.ID, requestIDFrom(r.Context()), request)
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusCreated, item)
}

func (s *Server) updateCaseTask(w http.ResponseWriter, r *http.Request) {
	var request cases.TaskPatch
	if err := decodeJSON(w, r, &request); err != nil {
		s.handleDecodeError(w, r, "Invalid case task update", err)
		return
	}
	if request.Version == 0 {
		request.Version = ifMatchVersion(r)
	}
	principal := principalFrom(r.Context())
	item, err := s.cases.UpdateTask(r.Context(), tenantFrom(r.Context()), r.PathValue("caseID"), r.PathValue("taskID"), principal.ID, requestIDFrom(r.Context()), request)
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, item)
}

func (s *Server) addCaseParticipant(w http.ResponseWriter, r *http.Request) {
	var request struct {
		cases.ParticipantInput
		Version int `json:"version"`
	}
	if err := decodeJSON(w, r, &request); err != nil {
		s.handleDecodeError(w, r, "Invalid case participant", err)
		return
	}
	if request.Version == 0 {
		request.Version = ifMatchVersion(r)
	}
	principal := principalFrom(r.Context())
	item, err := s.cases.AddParticipant(r.Context(), tenantFrom(r.Context()), r.PathValue("caseID"), principal.ID, requestIDFrom(r.Context()), request.ParticipantInput, request.Version)
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusCreated, item)
}

func (s *Server) addCaseObservable(w http.ResponseWriter, r *http.Request) {
	var request struct {
		cases.ObservableInput
		Version int `json:"version"`
	}
	if err := decodeJSON(w, r, &request); err != nil {
		s.handleDecodeError(w, r, "Invalid case observable", err)
		return
	}
	if request.Version == 0 {
		request.Version = ifMatchVersion(r)
	}
	principal := principalFrom(r.Context())
	item, err := s.cases.AddObservable(r.Context(), tenantFrom(r.Context()), r.PathValue("caseID"), principal.ID, requestIDFrom(r.Context()), request.ObservableInput, request.Version)
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusCreated, item)
}

func (s *Server) linkCaseIncident(w http.ResponseWriter, r *http.Request) {
	var request struct {
		IncidentID string `json:"incident_id"`
		Version    int    `json:"version"`
	}
	if err := decodeJSON(w, r, &request); err != nil {
		s.handleDecodeError(w, r, "Invalid case incident link", err)
		return
	}
	if request.Version == 0 {
		request.Version = ifMatchVersion(r)
	}
	principal := principalFrom(r.Context())
	item, err := s.cases.LinkIncident(r.Context(), tenantFrom(r.Context()), r.PathValue("caseID"), request.IncidentID, principal.ID, requestIDFrom(r.Context()), request.Version)
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusCreated, item)
}
