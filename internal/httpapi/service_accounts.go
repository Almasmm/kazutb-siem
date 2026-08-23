package httpapi

import (
	"errors"
	"net/http"

	"github.com/kcsp/platform/internal/serviceaccount"
	"github.com/kcsp/platform/internal/store"
)

func (s *Server) listServiceAccounts(w http.ResponseWriter, r *http.Request) {
	items, err := s.serviceAccounts.List(r.Context(), tenantFrom(r.Context()))
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, map[string]interface{}{"items": items, "total": len(items)})
}

func (s *Server) createServiceAccount(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	var request serviceaccount.CreateRequest
	if err := decodeJSON(w, r, &request); err != nil {
		s.handleDecodeError(w, r, "Invalid service account request", err)
		return
	}
	issue, err := s.serviceAccounts.Create(r.Context(), tenantFrom(r.Context()), principalFrom(r.Context()), request)
	if s.handleServiceAccountError(w, r, err) {
		return
	}
	s.json(w, http.StatusCreated, issue)
}

func (s *Server) rotateServiceAccount(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	var request serviceaccount.RotateRequest
	if err := decodeJSON(w, r, &request); err != nil {
		s.handleDecodeError(w, r, "Invalid service account rotation request", err)
		return
	}
	issue, err := s.serviceAccounts.Rotate(r.Context(), tenantFrom(r.Context()), r.PathValue("serviceAccountID"), principalFrom(r.Context()), request)
	if s.handleServiceAccountError(w, r, err) {
		return
	}
	s.json(w, http.StatusOK, issue)
}

func (s *Server) revokeServiceAccount(w http.ResponseWriter, r *http.Request) {
	account, err := s.serviceAccounts.Revoke(r.Context(), tenantFrom(r.Context()), r.PathValue("serviceAccountID"), principalFrom(r.Context()))
	if s.handleServiceAccountError(w, r, err) {
		return
	}
	s.json(w, http.StatusOK, account)
}

func (s *Server) handleServiceAccountError(w http.ResponseWriter, r *http.Request, err error) bool {
	if err == nil {
		return false
	}
	switch {
	case errors.Is(err, serviceaccount.ErrScopeDenied):
		s.problem(w, r, http.StatusForbidden, "service_account_scope_denied", "Service account scope denied", err.Error())
	case errors.Is(err, serviceaccount.ErrInvalidRequest):
		s.problem(w, r, http.StatusBadRequest, "validation_error", "Invalid service account request", err.Error())
	case errors.Is(err, store.ErrAlreadyExists):
		s.problem(w, r, http.StatusConflict, "service_account_exists", "Service account already exists", "A service account with this name already exists.")
	default:
		s.handleDomainError(w, r, err)
	}
	return true
}
