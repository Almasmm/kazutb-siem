package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/parser"
)

func (s *Server) listParsers(w http.ResponseWriter, r *http.Request) {
	items, err := s.parsers.List(r.Context(), tenantFrom(r.Context()))
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, map[string]interface{}{"items": items, "total": len(items)})
}

func (s *Server) listBuiltInParsers(w http.ResponseWriter, _ *http.Request) {
	items := parser.BuiltInDescriptors()
	s.json(w, http.StatusOK, map[string]interface{}{"items": items, "total": len(items)})
}

func (s *Server) getParserContent(w http.ResponseWriter, r *http.Request) {
	version, ok := parserVersion(w, r)
	if !ok {
		return
	}
	item, err := s.parsers.Content(r.Context(), tenantFrom(r.Context()), r.PathValue("parserID"), version)
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, item)
}

func (s *Server) createParserDraft(w http.ResponseWriter, r *http.Request) {
	s.createParserVersionRequest(w, r, "")
}

func (s *Server) createParserVersion(w http.ResponseWriter, r *http.Request) {
	s.createParserVersionRequest(w, r, r.PathValue("parserID"))
}

func (s *Server) createParserVersionRequest(w http.ResponseWriter, r *http.Request, parserID string) {
	var draft parser.ParserDraft
	if err := json.NewDecoder(io.LimitReader(r.Body, 2<<20)).Decode(&draft); err != nil {
		s.handleDecodeError(w, r, "Invalid parser draft", err)
		return
	}
	if parserID != "" {
		draft.ParserID = parserID
	}
	draft.RequestID = r.Header.Get("Idempotency-Key")
	principal := principalFrom(r.Context())
	item, err := s.parsers.CreateDraft(r.Context(), tenantFrom(r.Context()), principal.ID, draft)
	if errors.Is(err, parser.ErrInvalidDefinition) {
		s.problem(w, r, http.StatusBadRequest, "invalid_parser", "Invalid parser definition", err.Error())
		return
	}
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	if err = s.auditParser(r, principal.ID, "parser.draft.created", item); err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusCreated, item)
}

func (s *Server) validateParser(w http.ResponseWriter, r *http.Request) {
	version, ok := parserVersion(w, r)
	if !ok {
		return
	}
	principal := principalFrom(r.Context())
	item, err := s.parsers.Validate(r.Context(), tenantFrom(r.Context()), r.PathValue("parserID"), version)
	if errors.Is(err, parser.ErrValidationFailed) {
		s.json(w, http.StatusUnprocessableEntity, item)
		return
	}
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	if err = s.auditParser(r, principal.ID, "parser.validated", item); err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, item)
}

func (s *Server) publishParser(w http.ResponseWriter, r *http.Request) {
	version, ok := parserVersion(w, r)
	if !ok {
		return
	}
	principal := principalFrom(r.Context())
	item, err := s.parsers.Publish(r.Context(), tenantFrom(r.Context()), r.PathValue("parserID"), version)
	if errors.Is(err, parser.ErrValidationFailed) {
		s.problem(w, r, http.StatusConflict, "parser_not_validated", "Parser is not validated", "Validate all regression samples before publishing.")
		return
	}
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	if err = s.auditParser(r, principal.ID, "parser.published", item); err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, item)
}

func (s *Server) disableParser(w http.ResponseWriter, r *http.Request) {
	principal := principalFrom(r.Context())
	item, err := s.parsers.Disable(r.Context(), tenantFrom(r.Context()), r.PathValue("parserID"))
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	if err = s.auditParser(r, principal.ID, "parser.disabled", item); err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, item)
}

func (s *Server) simulateParser(w http.ResponseWriter, r *http.Request) {
	version, ok := parserVersion(w, r)
	if !ok {
		return
	}
	var request struct {
		Payload string `json:"payload"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, (1<<20)+1024)).Decode(&request); err != nil {
		s.handleDecodeError(w, r, "Invalid parser sample", err)
		return
	}
	result, err := s.parsers.Simulate(r.Context(), tenantFrom(r.Context()), r.PathValue("parserID"), version, request.Payload)
	if errors.Is(err, parser.ErrInvalidDefinition) || errors.Is(err, parser.ErrParse) {
		s.problem(w, r, http.StatusUnprocessableEntity, "parser_simulation_failed", "Parser simulation failed", err.Error())
		return
	}
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, result)
}

func parserVersion(w http.ResponseWriter, r *http.Request) (int, bool) {
	version, err := strconv.Atoi(r.PathValue("version"))
	if err != nil || version < 1 {
		http.Error(w, "invalid parser version", http.StatusBadRequest)
		return 0, false
	}
	return version, true
}

func (s *Server) auditParser(r *http.Request, actor, action string, item core.ParserContent) error {
	_, err := s.store.AppendAudit(r.Context(), core.AuditEntry{
		TenantID: tenantFrom(r.Context()), Actor: actor, Action: action, ResourceType: "parser", ResourceID: item.ParserID,
		Outcome: "success", Metadata: map[string]interface{}{"version": item.Version, "format": item.Spec.Format, "state": item.State},
	})
	return err
}
