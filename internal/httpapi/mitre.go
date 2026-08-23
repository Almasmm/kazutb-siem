package httpapi

import "net/http"

func (s *Server) mitreCoverage(w http.ResponseWriter, r *http.Request) {
	report, err := s.mitre.Coverage(r.Context(), tenantFrom(r.Context()))
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, report)
}
