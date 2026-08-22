package httpapi

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/threatintel"
)

func (s *Server) listThreatIntelFeeds(w http.ResponseWriter, r *http.Request) {
	items, err := s.threatIntel.Feeds(r.Context(), tenantFrom(r.Context()))
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, map[string]interface{}{"items": items, "total": len(items)})
}

func (s *Server) createThreatIntelFeed(w http.ResponseWriter, r *http.Request) {
	var draft threatintel.FeedDraft
	if err := decodeJSON(w, r, &draft); err != nil {
		s.handleDecodeError(w, r, "Invalid threat intelligence feed", err)
		return
	}
	principal := principalFrom(r.Context())
	feed, err := s.threatIntel.CreateFeed(r.Context(), tenantFrom(r.Context()), principal.ID, draft)
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	if err := s.auditThreatIntel(r, principal.ID, "threat_intel.feed.created", "threat_intel_feed", feed.ID,
		map[string]interface{}{"name": feed.Name, "kind": feed.Kind, "version": feed.Version}); err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	w.Header().Set("ETag", fmt.Sprintf("\"%d\"", feed.Version))
	s.json(w, http.StatusCreated, feed)
}

func (s *Server) getThreatIntelFeed(w http.ResponseWriter, r *http.Request) {
	feed, err := s.threatIntel.Feed(r.Context(), tenantFrom(r.Context()), r.PathValue("feedID"))
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	w.Header().Set("ETag", fmt.Sprintf("\"%d\"", feed.Version))
	s.json(w, http.StatusOK, feed)
}

func (s *Server) updateThreatIntelFeed(w http.ResponseWriter, r *http.Request) {
	var patch threatintel.FeedPatch
	if err := decodeJSON(w, r, &patch); err != nil {
		s.handleDecodeError(w, r, "Invalid threat intelligence feed update", err)
		return
	}
	if patch.Version == 0 {
		patch.Version = ifMatchVersion(r)
	}
	principal := principalFrom(r.Context())
	feed, err := s.threatIntel.UpdateFeed(r.Context(), tenantFrom(r.Context()), r.PathValue("feedID"), principal.ID, patch)
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	if err := s.auditThreatIntel(r, principal.ID, "threat_intel.feed.updated", "threat_intel_feed", feed.ID,
		map[string]interface{}{"state": feed.State, "version": feed.Version}); err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	w.Header().Set("ETag", fmt.Sprintf("\"%d\"", feed.Version))
	s.json(w, http.StatusOK, feed)
}

func (s *Server) listThreatIndicators(w http.ResponseWriter, r *http.Request) {
	items, err := s.threatIntel.Indicators(r.Context(), tenantFrom(r.Context()), core.ThreatIndicatorFilter{
		FeedID: strings.TrimSpace(r.URL.Query().Get("feed_id")),
		Type: core.ThreatIndicatorType(strings.TrimSpace(r.URL.Query().Get("type"))),
		State: strings.TrimSpace(r.URL.Query().Get("state")),
		Query: strings.TrimSpace(r.URL.Query().Get("q")),
		Limit: intQuery(r, "limit"),
	})
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, map[string]interface{}{"items": items, "total": len(items)})
}

func (s *Server) upsertThreatIndicator(w http.ResponseWriter, r *http.Request) {
	var draft threatintel.IndicatorDraft
	if err := decodeJSON(w, r, &draft); err != nil {
		s.handleDecodeError(w, r, "Invalid threat indicator", err)
		return
	}
	principal := principalFrom(r.Context())
	indicator, created, err := s.threatIntel.UpsertIndicator(r.Context(), tenantFrom(r.Context()), principal.ID, draft)
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	action := "threat_intel.indicator.updated"
	status := http.StatusOK
	if created {
		action = "threat_intel.indicator.created"
		status = http.StatusCreated
	}
	if err := s.auditThreatIntel(r, principal.ID, action, "threat_indicator", indicator.ID,
		map[string]interface{}{"type": indicator.Type, "feed_id": indicator.FeedID, "confidence": indicator.Confidence,
			"reputation": indicator.Reputation, "version": indicator.Version, "deduplicated": !created}); err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	w.Header().Set("ETag", fmt.Sprintf("\"%d\"", indicator.Version))
	s.json(w, status, indicator)
}

func (s *Server) getThreatIndicator(w http.ResponseWriter, r *http.Request) {
	indicator, err := s.threatIntel.Indicator(r.Context(), tenantFrom(r.Context()), r.PathValue("indicatorID"))
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	w.Header().Set("ETag", fmt.Sprintf("\"%d\"", indicator.Version))
	s.json(w, http.StatusOK, indicator)
}

func (s *Server) updateThreatIndicatorState(w http.ResponseWriter, r *http.Request) {
	var request struct {
		State   string `json:"state"`
		Version int    `json:"version"`
	}
	if err := decodeJSON(w, r, &request); err != nil {
		s.handleDecodeError(w, r, "Invalid threat indicator state", err)
		return
	}
	if request.Version == 0 {
		request.Version = ifMatchVersion(r)
	}
	principal := principalFrom(r.Context())
	indicator, err := s.threatIntel.SetIndicatorState(r.Context(), tenantFrom(r.Context()),
		r.PathValue("indicatorID"), principal.ID, request.State, request.Version)
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	if err := s.auditThreatIntel(r, principal.ID, "threat_intel.indicator.state_changed", "threat_indicator",
		indicator.ID, map[string]interface{}{"state": indicator.State, "version": indicator.Version}); err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	w.Header().Set("ETag", fmt.Sprintf("\"%d\"", indicator.Version))
	s.json(w, http.StatusOK, indicator)
}

func (s *Server) listThreatIndicatorMatches(w http.ResponseWriter, r *http.Request) {
	indicatorID := r.PathValue("indicatorID")
	if indicatorID == "" {
		indicatorID = strings.TrimSpace(r.URL.Query().Get("indicator_id"))
	}
	items, err := s.threatIntel.Matches(r.Context(), tenantFrom(r.Context()), indicatorID,
		strings.TrimSpace(r.URL.Query().Get("event_id")), intQuery(r, "limit"))
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, map[string]interface{}{"items": items, "total": len(items)})
}

func (s *Server) auditThreatIntel(r *http.Request, actor, action, resourceType, resourceID string, metadata map[string]interface{}) error {
	_, err := s.store.AppendAudit(r.Context(), core.AuditEntry{
		TenantID: tenantFrom(r.Context()), Actor: actor, Action: action, ResourceType: resourceType,
		ResourceID: resourceID, Outcome: "SUCCESS", RequestID: requestIDFrom(r.Context()), Metadata: metadata,
	})
	return err
}
