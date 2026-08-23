package httpapi

import (
	"errors"
	"net/http"
	"strings"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/entitygraph"
)

func (s *Server) listEntities(w http.ResponseWriter, r *http.Request) {
	items, err := s.entities.Entities(r.Context(), tenantFrom(r.Context()), core.EntityFilter{
		Type: core.EntityType(strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("type")))), Query: r.URL.Query().Get("q"),
		MinimumRisk: intQuery(r, "minimum_risk"), Limit: intQuery(r, "limit"),
	})
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, map[string]interface{}{"items": items, "total": len(items)})
}

func (s *Server) getEntity(w http.ResponseWriter, r *http.Request) {
	item, err := s.entities.Entity(r.Context(), tenantFrom(r.Context()), r.PathValue("entityID"))
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, item)
}

func (s *Server) getEntityGraph(w http.ResponseWriter, r *http.Request) {
	graph, err := s.entities.Graph(r.Context(), tenantFrom(r.Context()), r.PathValue("entityID"), intQuery(r, "depth"), intQuery(r, "limit"))
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, graph)
}

func (s *Server) listAssets(w http.ResponseWriter, r *http.Request) {
	items, err := s.entities.Assets(r.Context(), tenantFrom(r.Context()), core.EntityFilter{
		Query: r.URL.Query().Get("q"), MinimumRisk: intQuery(r, "minimum_risk"), Limit: intQuery(r, "limit"),
	})
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, map[string]interface{}{"items": items, "total": len(items)})
}

func (s *Server) getAsset(w http.ResponseWriter, r *http.Request) {
	item, err := s.entities.Asset(r.Context(), tenantFrom(r.Context()), r.PathValue("assetID"))
	if errors.Is(err, entitygraph.ErrNotAsset) {
		s.problem(w, r, http.StatusNotFound, "asset_not_found", "Asset not found", "The requested entity is not a managed asset.")
		return
	}
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, item)
}
