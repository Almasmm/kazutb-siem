package httpapi

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/soar"
)

func (s *Server) listSOARConnectors(w http.ResponseWriter, r *http.Request) {
	items, err := s.soar.Connectors(r.Context(), tenantFrom(r.Context()), core.SOARConnectorFilter{
		Kind: r.URL.Query().Get("kind"), State: r.URL.Query().Get("state"), Limit: intQuery(r, "limit"),
	})
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, map[string]interface{}{"items": items, "total": len(items)})
}

func (s *Server) createSOARConnector(w http.ResponseWriter, r *http.Request) {
	var draft soar.ConnectorDraft
	if err := decodeJSON(w, r, &draft); err != nil {
		s.handleDecodeError(w, r, "Invalid SOAR connector", err)
		return
	}
	principal := principalFrom(r.Context())
	connector, err := s.soar.CreateConnector(r.Context(), tenantFrom(r.Context()), principal.ID, draft)
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	if err := s.auditSOAR(r, principal.ID, "soar.connector.created", "soar_connector", connector.ID,
		map[string]interface{}{"kind": connector.Kind, "state": connector.State, "auth_type": connector.AuthType}); err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusCreated, connector)
}

func (s *Server) getSOARConnector(w http.ResponseWriter, r *http.Request) {
	connector, err := s.soar.Connector(r.Context(), tenantFrom(r.Context()), r.PathValue("connectorID"))
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	w.Header().Set("ETag", fmt.Sprintf("\"%d\"", connector.Version))
	s.json(w, http.StatusOK, connector)
}

func (s *Server) updateSOARConnector(w http.ResponseWriter, r *http.Request) {
	var patch soar.ConnectorPatch
	if err := decodeJSON(w, r, &patch); err != nil {
		s.handleDecodeError(w, r, "Invalid SOAR connector update", err)
		return
	}
	if patch.Version == 0 {
		patch.Version = ifMatchVersion(r)
	}
	principal := principalFrom(r.Context())
	connector, err := s.soar.UpdateConnector(r.Context(), tenantFrom(r.Context()),
		r.PathValue("connectorID"), principal.ID, patch)
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	if err := s.auditSOAR(r, principal.ID, "soar.connector.updated", "soar_connector", connector.ID,
		map[string]interface{}{"version": connector.Version, "state": connector.State}); err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	w.Header().Set("ETag", fmt.Sprintf("\"%d\"", connector.Version))
	s.json(w, http.StatusOK, connector)
}

func (s *Server) disableSOARConnector(w http.ResponseWriter, r *http.Request) {
	version := intQuery(r, "version")
	if version == 0 {
		version = ifMatchVersion(r)
	}
	principal := principalFrom(r.Context())
	connector, err := s.soar.DisableConnector(r.Context(), tenantFrom(r.Context()),
		r.PathValue("connectorID"), principal.ID, version)
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	if err := s.auditSOAR(r, principal.ID, "soar.connector.disabled", "soar_connector", connector.ID,
		map[string]interface{}{"version": connector.Version}); err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, connector)
}

func (s *Server) queueSOARConnectorTest(w http.ResponseWriter, r *http.Request) {
	var request struct {
		RequestID string `json:"request_id"`
	}
	if err := decodeJSON(w, r, &request); err != nil {
		s.handleDecodeError(w, r, "Invalid SOAR connector test", err)
		return
	}
	principal := principalFrom(r.Context())
	test, created, err := s.soar.QueueConnectorTest(r.Context(), tenantFrom(r.Context()),
		r.PathValue("connectorID"), principal.ID, request.RequestID)
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	status := http.StatusOK
	action := "soar.connector.test_replayed"
	if created {
		status = http.StatusAccepted
		action = "soar.connector.test_queued"
	}
	if err := s.auditSOAR(r, principal.ID, action, "soar_connector", test.ConnectorID,
		map[string]interface{}{"test_id": test.ID, "request_id": test.RequestID}); err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, status, test)
}

func (s *Server) listSOARConnectorTests(w http.ResponseWriter, r *http.Request) {
	items, err := s.soar.ConnectorTests(r.Context(), tenantFrom(r.Context()),
		strings.TrimSpace(r.PathValue("connectorID")), intQuery(r, "limit"))
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, map[string]interface{}{"items": items, "total": len(items)})
}
