package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kcsp/platform/internal/aisoc"
	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/detection"
	"github.com/kcsp/platform/internal/evidence"
	"github.com/kcsp/platform/internal/hunt"
	"github.com/kcsp/platform/internal/ingest"
	"github.com/kcsp/platform/internal/observability"
	"github.com/kcsp/platform/internal/pipeline"
	"github.com/kcsp/platform/internal/platform/auth"
	"github.com/kcsp/platform/internal/soar"
	"github.com/kcsp/platform/internal/soc"
	"github.com/kcsp/platform/internal/store"
	"github.com/kcsp/platform/internal/threatintel"
	"github.com/kcsp/platform/internal/ueba"
)

type contextKey string

const (
	principalKey contextKey = "principal"
	tenantKey    contextKey = "tenant"
	requestIDKey contextKey = "request-id"
)

type Server struct {
	store             store.Repository
	engine            *pipeline.Engine
	soc               *soc.Service
	auth              Authenticator
	logger            *slog.Logger
	mux               *http.ServeMux
	seed              func(context.Context) error
	startedAt         time.Time
	profile           string
	authMode          string
	gateway           *ingest.Gateway
	allowDirectIngest bool
	collectors        store.CollectorRegistry
	requireCollectors bool
	detections        *detection.Service
	hunts             store.HuntStore
	retention         store.RetentionStore
	evidence          *evidence.Service
	threatIntel       *threatintel.Service
	soar              *soar.Service
	ueba              *ueba.Service
	aiSOC             *aisoc.Service
}

type Authenticator interface {
	Authenticate(*http.Request) (auth.Principal, error)
}

type Config struct {
	Profile                     string
	AuthMode                    string
	Gateway                     *ingest.Gateway
	AllowDirectIngest           bool
	CollectorRegistry           store.CollectorRegistry
	RequireRegisteredCollectors bool
	DetectionService            *detection.Service
	HuntStore                   store.HuntStore
	RetentionStore              store.RetentionStore
	EvidenceService             *evidence.Service
	ThreatIntelService          *threatintel.Service
	SOARService                 *soar.Service
	UEBAService                 *ueba.Service
	AISOCService                *aisoc.Service
}

func New(repository store.Repository, engine *pipeline.Engine, socService *soc.Service, authenticator Authenticator, logger *slog.Logger, seed func(context.Context) error) http.Handler {
	return NewWithConfig(repository, engine, socService, authenticator, logger, seed, Config{Profile: "test", AuthMode: "demo", AllowDirectIngest: true})
}

func NewWithConfig(repository store.Repository, engine *pipeline.Engine, socService *soc.Service, authenticator Authenticator, logger *slog.Logger, seed func(context.Context) error, config Config) http.Handler {
	server := &Server{
		store: repository, engine: engine, soc: socService, auth: authenticator,
		logger: logger, mux: http.NewServeMux(), seed: seed, startedAt: time.Now().UTC(),
		profile: config.Profile, authMode: config.AuthMode,
		gateway: config.Gateway, allowDirectIngest: config.AllowDirectIngest,
		collectors: config.CollectorRegistry, requireCollectors: config.RequireRegisteredCollectors,
		detections: config.DetectionService, hunts: config.HuntStore, retention: config.RetentionStore,
		evidence: config.EvidenceService, threatIntel: config.ThreatIntelService, soar: config.SOARService,
		ueba: config.UEBAService, aiSOC: config.AISOCService,
	}
	server.routes()
	return server.middleware(server.mux)
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /health/live", s.live)
	s.mux.HandleFunc("GET /health/ready", s.ready)
	s.mux.HandleFunc("GET /healthz", s.live)
	s.mux.HandleFunc("GET /readyz", s.ready)
	s.mux.HandleFunc("GET /metrics", s.metrics)

	s.mux.Handle("GET /api/v1/session", s.protect("platform.overview.read", http.HandlerFunc(s.session)))
	s.mux.Handle("GET /api/v1/overview", s.protect("platform.overview.read", http.HandlerFunc(s.overview)))
	s.mux.Handle("GET /api/v1/events", s.protect("siem.events.read", http.HandlerFunc(s.listEvents)))
	s.mux.Handle("GET /api/v1/events/{eventID}", s.protect("siem.events.read", http.HandlerFunc(s.getEvent)))
	if s.allowDirectIngest {
		s.mux.Handle("POST /api/v1/events", s.protect("siem.events.ingest", http.HandlerFunc(s.ingestEvent)))
	}
	if s.gateway != nil {
		s.mux.Handle("POST /api/v1/ingest/events", s.protect("siem.events.ingest", http.HandlerFunc(s.queueEvent)))
	}
	if s.collectors != nil {
		s.mux.Handle("GET /api/v1/collectors", s.protect("platform.collectors.read", http.HandlerFunc(s.listCollectors)))
		s.mux.Handle("POST /api/v1/collectors", s.protect("platform.collectors.manage", http.HandlerFunc(s.registerCollector)))
		s.mux.Handle("PATCH /api/v1/collectors/{collectorID}", s.protect("platform.collectors.manage", http.HandlerFunc(s.updateCollector)))
		s.mux.Handle("POST /api/v1/collectors/heartbeat", s.protect("platform.collectors.heartbeat", http.HandlerFunc(s.collectorHeartbeat)))
	}
	if s.detections != nil {
		s.mux.Handle("GET /api/v1/detection/content", s.protect("siem.rules.read", http.HandlerFunc(s.listDetectionContent)))
		s.mux.Handle("POST /api/v1/detection/content", s.protect("siem.rules.write", http.HandlerFunc(s.createDetectionDraft)))
		s.mux.Handle("POST /api/v1/detection/content/{ruleID}/versions/{version}/validate", s.protect("siem.rules.write", http.HandlerFunc(s.validateDetectionContent)))
		s.mux.Handle("POST /api/v1/detection/content/{ruleID}/versions/{version}/publish", s.protect("siem.rules.publish", http.HandlerFunc(s.publishDetectionContent)))
		s.mux.Handle("POST /api/v1/detection/content/{ruleID}/disable", s.protect("siem.rules.publish", http.HandlerFunc(s.disableDetectionContent)))
		s.mux.Handle("POST /api/v1/detection/content/{ruleID}/rollback", s.protect("siem.rules.publish", http.HandlerFunc(s.rollbackDetectionContent)))
		s.mux.Handle("POST /api/v1/detection/content/{ruleID}/simulate", s.protect("siem.rules.write", http.HandlerFunc(s.simulateDetectionContent)))
		s.mux.Handle("POST /api/v1/detection/content/{ruleID}/replay", s.protect("siem.rules.write", http.HandlerFunc(s.replayDetectionContent)))
	}
	if s.hunts != nil {
		s.mux.Handle("POST /api/v1/hunt/search", s.protect("siem.hunt.execute", http.HandlerFunc(s.searchHunt)))
		s.mux.Handle("GET /api/v1/hunt/saved", s.protect("siem.hunt.read", http.HandlerFunc(s.listSavedHunts)))
		s.mux.Handle("POST /api/v1/hunt/saved", s.protect("siem.hunt.manage", http.HandlerFunc(s.createSavedHunt)))
		s.mux.Handle("GET /api/v1/hunt/saved/{huntID}", s.protect("siem.hunt.read", http.HandlerFunc(s.getSavedHunt)))
		s.mux.Handle("PATCH /api/v1/hunt/saved/{huntID}", s.protect("siem.hunt.manage", http.HandlerFunc(s.updateSavedHunt)))
		s.mux.Handle("DELETE /api/v1/hunt/saved/{huntID}", s.protect("siem.hunt.manage", http.HandlerFunc(s.deleteSavedHunt)))
		s.mux.Handle("POST /api/v1/hunt/saved/{huntID}/execute", s.protect("siem.hunt.execute", http.HandlerFunc(s.executeSavedHunt)))
		s.mux.Handle("GET /api/v1/hunt/executions", s.protect("siem.hunt.read", http.HandlerFunc(s.listHuntExecutions)))
	}
	if s.retention != nil {
		s.mux.Handle("GET /api/v1/retention", s.protect("platform.retention.read", http.HandlerFunc(s.getRetentionPolicy)))
		s.mux.Handle("PATCH /api/v1/retention", s.protect("platform.retention.manage", http.HandlerFunc(s.updateRetentionPolicy)))
	}
	if s.evidence != nil {
		s.mux.Handle("GET /api/v1/evidence", s.protect("soc.evidence.read", http.HandlerFunc(s.listEvidence)))
		s.mux.Handle("POST /api/v1/evidence", s.protect("soc.evidence.write", http.HandlerFunc(s.uploadEvidence)))
		s.mux.Handle("GET /api/v1/evidence/{evidenceID}", s.protect("soc.evidence.read", http.HandlerFunc(s.getEvidence)))
		s.mux.Handle("GET /api/v1/evidence/{evidenceID}/content", s.protect("soc.evidence.read", http.HandlerFunc(s.downloadEvidence)))
		s.mux.Handle("POST /api/v1/evidence/{evidenceID}/verify", s.protect("soc.evidence.read", http.HandlerFunc(s.verifyEvidence)))
		s.mux.Handle("GET /api/v1/evidence/{evidenceID}/custody", s.protect("soc.evidence.read", http.HandlerFunc(s.listEvidenceCustody)))
	}
	if s.threatIntel != nil {
		s.mux.Handle("GET /api/v1/threat-intel/feeds", s.protect("ti.indicators.read", http.HandlerFunc(s.listThreatIntelFeeds)))
		s.mux.Handle("POST /api/v1/threat-intel/feeds", s.protect("ti.indicators.manage", http.HandlerFunc(s.createThreatIntelFeed)))
		s.mux.Handle("GET /api/v1/threat-intel/feeds/{feedID}", s.protect("ti.indicators.read", http.HandlerFunc(s.getThreatIntelFeed)))
		s.mux.Handle("PATCH /api/v1/threat-intel/feeds/{feedID}", s.protect("ti.indicators.manage", http.HandlerFunc(s.updateThreatIntelFeed)))
		s.mux.Handle("GET /api/v1/threat-intel/indicators", s.protect("ti.indicators.read", http.HandlerFunc(s.listThreatIndicators)))
		s.mux.Handle("POST /api/v1/threat-intel/indicators", s.protect("ti.indicators.manage", http.HandlerFunc(s.upsertThreatIndicator)))
		s.mux.Handle("GET /api/v1/threat-intel/indicators/{indicatorID}", s.protect("ti.indicators.read", http.HandlerFunc(s.getThreatIndicator)))
		s.mux.Handle("PATCH /api/v1/threat-intel/indicators/{indicatorID}", s.protect("ti.indicators.manage", http.HandlerFunc(s.updateThreatIndicatorState)))
		s.mux.Handle("GET /api/v1/threat-intel/indicators/{indicatorID}/matches", s.protect("ti.indicators.read", http.HandlerFunc(s.listThreatIndicatorMatches)))
		s.mux.Handle("POST /api/v1/threat-intel/indicators/{indicatorID}/retrosearch", s.protect("ti.indicators.manage", http.HandlerFunc(s.retrosearchThreatIndicator)))
		s.mux.Handle("GET /api/v1/threat-intel/matches", s.protect("ti.indicators.read", http.HandlerFunc(s.listThreatIndicatorMatches)))
		s.mux.Handle("POST /api/v1/threat-intel/stix/import", s.protect("ti.indicators.manage", http.HandlerFunc(s.importThreatIntelSTIX)))
		s.mux.Handle("GET /api/v1/threat-intel/stix/export", s.protect("ti.indicators.read", http.HandlerFunc(s.exportThreatIntelSTIX)))
	}
	if s.soar != nil {
		s.mux.Handle("GET /api/v1/soar/playbooks", s.protect("soar.playbooks.read", http.HandlerFunc(s.listSOARPlaybooks)))
		s.mux.Handle("POST /api/v1/soar/playbooks", s.protect("soar.playbooks.write", http.HandlerFunc(s.createSOARPlaybook)))
		s.mux.Handle("GET /api/v1/soar/playbooks/{playbookID}", s.protect("soar.playbooks.read", http.HandlerFunc(s.getSOARPlaybook)))
		s.mux.Handle("POST /api/v1/soar/playbooks/{playbookID}/versions", s.protect("soar.playbooks.write", http.HandlerFunc(s.createSOARVersion)))
		s.mux.Handle("POST /api/v1/soar/playbooks/{playbookID}/versions/{version}/validate", s.protect("soar.playbooks.write", http.HandlerFunc(s.validateSOARVersion)))
		s.mux.Handle("POST /api/v1/soar/playbooks/{playbookID}/versions/{version}/publish", s.protect("soar.playbooks.write", http.HandlerFunc(s.publishSOARVersion)))
		s.mux.Handle("POST /api/v1/soar/playbooks/{playbookID}/disable", s.protect("soar.playbooks.write", http.HandlerFunc(s.disableSOARPlaybook)))
		s.mux.Handle("GET /api/v1/soar/executions", s.protect("soar.playbooks.read", http.HandlerFunc(s.listSOARExecutions)))
		s.mux.Handle("POST /api/v1/soar/executions", s.protect("soar.playbooks.execute", http.HandlerFunc(s.startSOARExecution)))
		s.mux.Handle("GET /api/v1/soar/executions/{executionID}", s.protect("soar.playbooks.read", http.HandlerFunc(s.getSOARExecution)))
		s.mux.Handle("POST /api/v1/soar/executions/{executionID}/nodes/{nodeID}/complete", s.protect("soar.playbooks.execute", http.HandlerFunc(s.completeSOARManualTask)))
		s.mux.Handle("GET /api/v1/soar/approvals", s.protect("soar.actions.approve", http.HandlerFunc(s.listSOARApprovals)))
		s.mux.Handle("POST /api/v1/soar/approvals/{approvalID}/decisions", s.protect("soar.actions.approve", http.HandlerFunc(s.decideSOARApproval)))
		s.mux.Handle("GET /api/v1/soar/action-attempts", s.protect("soar.playbooks.read", http.HandlerFunc(s.listSOARActionAttempts)))
		s.mux.Handle("GET /api/v1/soar/connectors", s.protect("soar.connectors.read", http.HandlerFunc(s.listSOARConnectors)))
		s.mux.Handle("POST /api/v1/soar/connectors", s.protect("soar.connectors.manage", http.HandlerFunc(s.createSOARConnector)))
		s.mux.Handle("GET /api/v1/soar/connectors/{connectorID}", s.protect("soar.connectors.read", http.HandlerFunc(s.getSOARConnector)))
		s.mux.Handle("PATCH /api/v1/soar/connectors/{connectorID}", s.protect("soar.connectors.manage", http.HandlerFunc(s.updateSOARConnector)))
		s.mux.Handle("POST /api/v1/soar/connectors/{connectorID}/disable", s.protect("soar.connectors.manage", http.HandlerFunc(s.disableSOARConnector)))
		s.mux.Handle("POST /api/v1/soar/connectors/{connectorID}/tests", s.protect("soar.connectors.test", http.HandlerFunc(s.queueSOARConnectorTest)))
		s.mux.Handle("GET /api/v1/soar/connectors/{connectorID}/tests", s.protect("soar.connectors.read", http.HandlerFunc(s.listSOARConnectorTests)))
	}
	if s.ueba != nil {
		s.mux.Handle("GET /api/v1/ueba/anomalies", s.protect("ueba.read", http.HandlerFunc(s.listUEBAAnomalies)))
		s.mux.Handle("GET /api/v1/ueba/entities/{entityType}/{entityID}", s.protect("ueba.read", http.HandlerFunc(s.getUEBABaseline)))
		s.mux.Handle("POST /api/v1/ueba/anomalies/{anomalyID}/feedback", s.protect("ueba.feedback", http.HandlerFunc(s.updateUEBAFeedback)))
	}
	if s.aiSOC != nil {
		s.mux.Handle("GET /api/v1/ai-soc/policy", s.protect("ai.read", http.HandlerFunc(s.getAISOCPolicy)))
		s.mux.Handle("PATCH /api/v1/ai-soc/policy", s.protect("ai.policy.manage", http.HandlerFunc(s.updateAISOCPolicy)))
		s.mux.Handle("GET /api/v1/ai-soc/requests", s.protect("ai.read", http.HandlerFunc(s.listAISOCRequests)))
		s.mux.Handle("POST /api/v1/ai-soc/requests", s.protect("ai.request", http.HandlerFunc(s.createAISOCRequest)))
		s.mux.Handle("GET /api/v1/ai-soc/requests/{requestID}", s.protect("ai.read", http.HandlerFunc(s.getAISOCRequest)))
		s.mux.Handle("POST /api/v1/ai-soc/requests/{requestID}/decisions", s.protect("ai.decide", http.HandlerFunc(s.decideAISOCRequest)))
	}
	s.mux.Handle("GET /api/v1/findings", s.protect("siem.findings.read", http.HandlerFunc(s.listFindings)))
	s.mux.Handle("GET /api/v1/alerts", s.protect("soc.alerts.read", http.HandlerFunc(s.listAlerts)))
	s.mux.Handle("GET /api/v1/alerts/{alertID}", s.protect("soc.alerts.read", http.HandlerFunc(s.getAlert)))
	s.mux.Handle("PATCH /api/v1/alerts/{alertID}", s.protect("soc.alerts.manage", http.HandlerFunc(s.updateAlert)))
	s.mux.Handle("GET /api/v1/incidents", s.protect("soc.incidents.read", http.HandlerFunc(s.listIncidents)))
	s.mux.Handle("POST /api/v1/incidents", s.protect("soc.incidents.create", http.HandlerFunc(s.createIncident)))
	s.mux.Handle("GET /api/v1/incidents/{incidentID}", s.protect("soc.incidents.read", http.HandlerFunc(s.getIncident)))
	s.mux.Handle("PATCH /api/v1/incidents/{incidentID}", s.protect("soc.incidents.manage", http.HandlerFunc(s.updateIncident)))
	s.mux.Handle("GET /api/v1/rules", s.protect("detection.rules.read", http.HandlerFunc(s.listRules)))
	s.mux.Handle("GET /api/v1/audit", s.protect("platform.audit.read", http.HandlerFunc(s.listAudit)))
	if s.seed != nil {
		s.mux.Handle("POST /api/v1/demo/reset", s.protect("platform.demo.reset", http.HandlerFunc(s.resetDemo)))
	}
}

func (s *Server) protect(permission string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, err := s.auth.Authenticate(r)
		if err != nil {
			s.problem(w, r, http.StatusUnauthorized, "authentication_required", "Authentication required", "Use an authorized bearer credential.")
			return
		}
		if !principal.Can(permission) {
			s.problem(w, r, http.StatusForbidden, "permission_denied", "Permission denied", "The principal does not have "+permission+".")
			return
		}
		tenantID := tenantIDFromHeader(r.Header.Values("X-KCSP-Tenant-ID"))
		if !principal.CanAccessTenant(tenantID) {
			s.problem(w, r, http.StatusForbidden, "tenant_denied", "Tenant access denied", "The requested tenant is not in the principal membership.")
			return
		}
		ctx := context.WithValue(r.Context(), principalKey, principal)
		ctx = context.WithValue(ctx, tenantKey, tenantID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := strings.TrimSpace(r.Header.Get("X-Request-ID"))
		if requestID == "" {
			requestID = core.NewID("req")
		}
		w.Header().Set("X-Request-ID", requestID)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		w.Header().Set("Cache-Control", "no-store")
		origin := r.Header.Get("Origin")
		if origin == "http://localhost:5173" || origin == "http://127.0.0.1:5173" || origin == "http://localhost:3000" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-KCSP-Tenant-ID, X-KCSP-Event-Format, X-KCSP-Event-ID, X-KCSP-Event-Timestamp, X-Request-ID, If-Match")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, OPTIONS")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		started := time.Now()
		ctx := context.WithValue(r.Context(), requestIDKey, requestID)
		recorder := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(recorder, r.WithContext(ctx))
		observability.Default.ObserveAPI(time.Since(started))
		s.logger.Debug("request completed", "method", r.Method, "path", r.URL.Path, "request_id", requestID, "duration", time.Since(started))
	})
}

func (s *Server) live(w http.ResponseWriter, r *http.Request) {
	s.json(w, http.StatusOK, map[string]interface{}{"status": "ok", "service": "kcsp-api", "time": time.Now().UTC()})
}

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	if err := s.store.Health(r.Context()); err != nil {
		s.problem(w, r, http.StatusServiceUnavailable, "dependency_unavailable", "Service unavailable", "PostgreSQL is not ready.")
		return
	}
	auditValid, err := s.store.VerifyAudit(r.Context(), core.DefaultTenantID)
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	if s.evidence != nil {
		if err := s.evidence.Health(r.Context()); err != nil {
			s.problem(w, r, http.StatusServiceUnavailable, "evidence_unavailable", "Service unavailable", "Immutable evidence storage is not ready.")
			return
		}
	}
	s.json(w, http.StatusOK, map[string]interface{}{"status": "ready", "profile": s.profile, "audit_chain_valid": auditValid})
}

func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	observability.Default.WritePrometheus(w)
}

func (s *Server) session(w http.ResponseWriter, r *http.Request) {
	principal := principalFrom(r.Context())
	permissions := make([]string, 0, len(principal.Permissions))
	for permission := range principal.Permissions {
		permissions = append(permissions, permission)
	}
	s.json(w, http.StatusOK, map[string]interface{}{
		"principal":   map[string]string{"id": principal.ID, "display_name": principal.DisplayName, "role": principal.Role},
		"tenant":      map[string]string{"id": tenantFrom(r.Context()), "name": "K. Kulazhanov University"},
		"permissions": permissions, "locale": "ru-KZ", "timezone": "Asia/Qyzylorda", "auth_mode": s.authMode,
	})
}

func (s *Server) overview(w http.ResponseWriter, r *http.Request) {
	overview, err := s.store.Overview(r.Context(), tenantFrom(r.Context()))
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, overview)
}

func (s *Server) listEvents(w http.ResponseWriter, r *http.Request) {
	filter := store.EventFilter{
		Query: r.URL.Query().Get("q"), Category: r.URL.Query().Get("category"),
		Severity: intQuery(r, "severity"), Limit: intQuery(r, "limit"),
	}
	items, err := s.store.ListEvents(r.Context(), tenantFrom(r.Context()), filter)
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, map[string]interface{}{"items": items, "total": len(items)})
}

func (s *Server) getEvent(w http.ResponseWriter, r *http.Request) {
	event, err := s.store.GetEvent(r.Context(), tenantFrom(r.Context()), r.PathValue("eventID"))
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, event)
}

func (s *Server) ingestEvent(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var input core.CanonicalEvent
	if err := decodeOne(json.NewDecoder(r.Body), &input); err != nil {
		s.handleDecodeError(w, r, "Invalid event payload", err)
		return
	}
	result, err := s.engine.Ingest(r.Context(), tenantFrom(r.Context()), input)
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	status := http.StatusCreated
	if result.Duplicate {
		status = http.StatusOK
	}
	s.json(w, status, result)
}

func (s *Server) queueEvent(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, ingest.MaxEventBytes)
	payload, err := io.ReadAll(r.Body)
	if err != nil {
		s.handleDecodeError(w, r, "Invalid event payload", err)
		return
	}
	principal := principalFrom(r.Context())
	collectorID := principal.ID
	if s.collectors != nil {
		collector, lookupErr := s.collectors.CollectorBySubject(r.Context(), tenantFrom(r.Context()), principal.ID)
		switch {
		case lookupErr == nil && collector.State == "ACTIVE":
			collectorID = collector.ID
		case lookupErr == nil:
			s.problem(w, r, http.StatusForbidden, "collector_revoked", "Collector revoked", "The collector identity is not active.")
			return
		case s.requireCollectors && errors.Is(lookupErr, store.ErrNotFound):
			s.problem(w, r, http.StatusForbidden, "collector_not_registered", "Collector not registered", "The service identity is not bound to an active collector in this tenant.")
			return
		case s.requireCollectors:
			s.handleDomainError(w, r, lookupErr)
			return
		}
	}
	format := strings.TrimSpace(r.Header.Get("X-KCSP-Event-Format"))
	var receipt ingest.Receipt
	if format == "" || format == ingest.FormatCanonicalJSON {
		receipt, err = s.gateway.SubmitJSON(r.Context(), tenantFrom(r.Context()), collectorID, payload)
	} else {
		var eventTimestamp time.Time
		if value := strings.TrimSpace(r.Header.Get("X-KCSP-Event-Timestamp")); value != "" {
			eventTimestamp, err = time.Parse(time.RFC3339Nano, value)
			if err != nil {
				s.problem(w, r, http.StatusBadRequest, "validation_error", "Invalid event timestamp", "X-KCSP-Event-Timestamp must be RFC3339.")
				return
			}
		}
		receipt, err = s.gateway.SubmitRaw(r.Context(), tenantFrom(r.Context()), collectorID, ingest.RawSubmission{
			Format: format, ContentType: r.Header.Get("Content-Type"), EventID: r.Header.Get("X-KCSP-Event-ID"),
			EventTimestamp: eventTimestamp, Payload: payload,
		})
	}
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusAccepted, receipt)
}

func (s *Server) listCollectors(w http.ResponseWriter, r *http.Request) {
	items, err := s.collectors.ListCollectors(r.Context(), tenantFrom(r.Context()))
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, map[string]interface{}{"items": items, "total": len(items)})
}

func (s *Server) registerCollector(w http.ResponseWriter, r *http.Request) {
	var request struct {
		ID           string   `json:"collector_id"`
		Name         string   `json:"name"`
		Type         string   `json:"type"`
		AuthSubject  string   `json:"auth_subject"`
		Capabilities []string `json:"capabilities"`
	}
	if err := decodeJSON(w, r, &request); err != nil {
		s.handleDecodeError(w, r, "Invalid collector registration", err)
		return
	}
	if strings.TrimSpace(request.ID) == "" {
		request.ID = core.NewID("col")
	}
	collector, err := s.collectors.RegisterCollector(r.Context(), core.Collector{
		ID: request.ID, TenantID: tenantFrom(r.Context()), Name: request.Name, Type: request.Type,
		AuthSubject: request.AuthSubject, Capabilities: request.Capabilities,
	})
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	principal := principalFrom(r.Context())
	if _, err := s.store.AppendAudit(r.Context(), core.AuditEntry{
		TenantID: collector.TenantID, Actor: principal.ID, Action: "collector.registered", ResourceType: "collector",
		ResourceID: collector.ID, Outcome: "SUCCESS", RequestID: requestIDFrom(r.Context()),
		Metadata: map[string]interface{}{"auth_subject": collector.AuthSubject, "type": collector.Type},
	}); err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusCreated, collector)
}

func (s *Server) updateCollector(w http.ResponseWriter, r *http.Request) {
	var request struct {
		State string `json:"state"`
	}
	if err := decodeJSON(w, r, &request); err != nil {
		s.handleDecodeError(w, r, "Invalid collector update", err)
		return
	}
	collector, err := s.collectors.SetCollectorState(r.Context(), tenantFrom(r.Context()), r.PathValue("collectorID"), request.State)
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	principal := principalFrom(r.Context())
	if _, err := s.store.AppendAudit(r.Context(), core.AuditEntry{
		TenantID: collector.TenantID, Actor: principal.ID, Action: "collector.state_changed", ResourceType: "collector",
		ResourceID: collector.ID, Outcome: "SUCCESS", RequestID: requestIDFrom(r.Context()), Metadata: map[string]interface{}{"state": collector.State},
	}); err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, collector)
}

func (s *Server) collectorHeartbeat(w http.ResponseWriter, r *http.Request) {
	var heartbeat core.CollectorHeartbeat
	if err := decodeJSON(w, r, &heartbeat); err != nil {
		s.handleDecodeError(w, r, "Invalid collector heartbeat", err)
		return
	}
	principal := principalFrom(r.Context())
	collector, err := s.collectors.HeartbeatCollector(r.Context(), tenantFrom(r.Context()), principal.ID, heartbeat, remoteIP(r.RemoteAddr))
	if errors.Is(err, store.ErrNotFound) {
		s.problem(w, r, http.StatusForbidden, "collector_not_registered", "Collector not registered", "The service identity is not bound to an active collector in this tenant.")
		return
	}
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, collector)
}

func remoteIP(address string) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(address))
	if err == nil {
		return host
	}
	return strings.TrimSpace(address)
}

func (s *Server) listDetectionContent(w http.ResponseWriter, r *http.Request) {
	items, err := s.detections.List(r.Context(), tenantFrom(r.Context()))
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, map[string]interface{}{"items": items, "total": len(items)})
}

func (s *Server) createDetectionDraft(w http.ResponseWriter, r *http.Request) {
	var request struct {
		RuleID                  string                 `json:"rule_id"`
		Version                 string                 `json:"version"`
		SigmaYAML               string                 `json:"sigma_yaml"`
		PositiveTests           []core.DetectionSample `json:"positive_tests"`
		NegativeTests           []core.DetectionSample `json:"negative_tests"`
		PerformanceBudgetMicros int64                  `json:"performance_budget_micros"`
	}
	if err := decodeJSON(w, r, &request); err != nil {
		s.handleDecodeError(w, r, "Invalid detection draft", err)
		return
	}
	principal := principalFrom(r.Context())
	content, err := s.detections.CreateDraft(r.Context(), core.DetectionContent{
		TenantID: tenantFrom(r.Context()), RuleID: request.RuleID, Version: request.Version, SigmaYAML: request.SigmaYAML,
		PositiveTests: request.PositiveTests, NegativeTests: request.NegativeTests,
		PerformanceBudgetMicros: request.PerformanceBudgetMicros, CreatedBy: principal.ID,
	})
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	if err := s.auditDetection(r, principal.ID, "detection.draft_created", content); err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusCreated, content)
}

func (s *Server) validateDetectionContent(w http.ResponseWriter, r *http.Request) {
	content, err := s.detections.Validate(r.Context(), tenantFrom(r.Context()), r.PathValue("ruleID"), r.PathValue("version"))
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	principal := principalFrom(r.Context())
	if err := s.auditDetection(r, principal.ID, "detection.validated", content); err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, content)
}

func (s *Server) publishDetectionContent(w http.ResponseWriter, r *http.Request) {
	content, err := s.detections.Publish(r.Context(), tenantFrom(r.Context()), r.PathValue("ruleID"), r.PathValue("version"))
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	principal := principalFrom(r.Context())
	if err := s.auditDetection(r, principal.ID, "detection.published", content); err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, content)
}

func (s *Server) disableDetectionContent(w http.ResponseWriter, r *http.Request) {
	content, err := s.detections.Disable(r.Context(), tenantFrom(r.Context()), r.PathValue("ruleID"))
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	principal := principalFrom(r.Context())
	if err := s.auditDetection(r, principal.ID, "detection.disabled", content); err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, content)
}

func (s *Server) rollbackDetectionContent(w http.ResponseWriter, r *http.Request) {
	content, err := s.detections.Rollback(r.Context(), tenantFrom(r.Context()), r.PathValue("ruleID"))
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	principal := principalFrom(r.Context())
	if err := s.auditDetection(r, principal.ID, "detection.rolled_back", content); err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, content)
}

func (s *Server) simulateDetectionContent(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Version string              `json:"version"`
		Event   core.CanonicalEvent `json:"event"`
	}
	if err := decodeJSON(w, r, &request); err != nil {
		s.handleDecodeError(w, r, "Invalid detection simulation", err)
		return
	}
	matched, fields, err := s.detections.Simulate(r.Context(), tenantFrom(r.Context()), r.PathValue("ruleID"), request.Version, request.Event)
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, map[string]interface{}{"matched": matched, "matched_fields": fields})
}

func (s *Server) replayDetectionContent(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Version string    `json:"version"`
		Start   time.Time `json:"start"`
		End     time.Time `json:"end"`
		Limit   int       `json:"limit"`
	}
	if err := decodeJSON(w, r, &request); err != nil {
		s.handleDecodeError(w, r, "Invalid detection replay", err)
		return
	}
	report, err := s.detections.Replay(r.Context(), tenantFrom(r.Context()), r.PathValue("ruleID"), request.Version, request.Start, request.End, request.Limit)
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, report)
}

func (s *Server) auditDetection(r *http.Request, actor, action string, content core.DetectionContent) error {
	_, err := s.store.AppendAudit(r.Context(), core.AuditEntry{
		TenantID: content.TenantID, Actor: actor, Action: action, ResourceType: "detection_rule",
		ResourceID: content.RuleID, Outcome: "SUCCESS", RequestID: requestIDFrom(r.Context()),
		Metadata: map[string]interface{}{"version": content.Version, "state": content.State},
	})
	return err
}

func (s *Server) listFindings(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListFindings(r.Context(), tenantFrom(r.Context()), r.URL.Query().Get("event_id"), intQuery(r, "limit"))
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, map[string]interface{}{"items": items, "total": len(items)})
}

func (s *Server) listAlerts(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListAlerts(r.Context(), tenantFrom(r.Context()), store.AlertFilter{
		Status: r.URL.Query().Get("status"), Severity: core.Severity(strings.ToUpper(r.URL.Query().Get("severity"))),
		Assignee: r.URL.Query().Get("assignee"), Query: r.URL.Query().Get("q"), Limit: intQuery(r, "limit"),
	})
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, map[string]interface{}{"items": items, "total": len(items)})
}

func (s *Server) getAlert(w http.ResponseWriter, r *http.Request) {
	alert, err := s.store.GetAlert(r.Context(), tenantFrom(r.Context()), r.PathValue("alertID"))
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	w.Header().Set("ETag", fmt.Sprintf("\"%d\"", alert.Version))
	s.json(w, http.StatusOK, alert)
}

func (s *Server) updateAlert(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Status      string `json:"status"`
		Assignee    string `json:"assignee"`
		Disposition string `json:"disposition"`
		Comment     string `json:"comment"`
		Version     int    `json:"version"`
	}
	if err := decodeJSON(w, r, &request); err != nil {
		s.handleDecodeError(w, r, "Invalid alert update", err)
		return
	}
	if request.Version == 0 {
		request.Version = ifMatchVersion(r)
	}
	principal := principalFrom(r.Context())
	alert, err := s.soc.UpdateAlert(r.Context(), tenantFrom(r.Context()), r.PathValue("alertID"), principal.ID, requestIDFrom(r.Context()), soc.AlertPatch{
		Status: request.Status, Assignee: request.Assignee, Disposition: request.Disposition, Comment: request.Comment, Version: request.Version,
	})
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	w.Header().Set("ETag", fmt.Sprintf("\"%d\"", alert.Version))
	s.json(w, http.StatusOK, alert)
}

func (s *Server) listIncidents(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListIncidents(r.Context(), tenantFrom(r.Context()), store.IncidentFilter{
		Status: r.URL.Query().Get("status"), Severity: core.Severity(strings.ToUpper(r.URL.Query().Get("severity"))),
		Query: r.URL.Query().Get("q"), Limit: intQuery(r, "limit"),
	})
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, map[string]interface{}{"items": items, "total": len(items)})
}

func (s *Server) getIncident(w http.ResponseWriter, r *http.Request) {
	incident, err := s.store.GetIncident(r.Context(), tenantFrom(r.Context()), r.PathValue("incidentID"))
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	w.Header().Set("ETag", fmt.Sprintf("\"%d\"", incident.Version))
	s.json(w, http.StatusOK, incident)
}

func (s *Server) createIncident(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Title    string   `json:"title"`
		Summary  string   `json:"summary"`
		Assignee string   `json:"assignee"`
		AlertIDs []string `json:"alert_ids"`
	}
	if err := decodeJSON(w, r, &request); err != nil {
		s.handleDecodeError(w, r, "Invalid incident", err)
		return
	}
	principal := principalFrom(r.Context())
	incident, duplicate, err := s.soc.CreateIncident(r.Context(), tenantFrom(r.Context()), principal.ID, soc.CreateIncidentInput{
		Title: request.Title, Summary: request.Summary, Assignee: request.Assignee,
		AlertIDs: request.AlertIDs, RequestID: requestIDFrom(r.Context()),
	})
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	status := http.StatusCreated
	if duplicate {
		status = http.StatusOK
	}
	s.json(w, status, incident)
}

func (s *Server) updateIncident(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Status        string `json:"status"`
		Assignee      string `json:"assignee"`
		Disposition   string `json:"disposition"`
		ClosureReason string `json:"closure_reason"`
		Comment       string `json:"comment"`
		Version       int    `json:"version"`
	}
	if err := decodeJSON(w, r, &request); err != nil {
		s.handleDecodeError(w, r, "Invalid incident update", err)
		return
	}
	if request.Version == 0 {
		request.Version = ifMatchVersion(r)
	}
	principal := principalFrom(r.Context())
	incident, err := s.soc.UpdateIncident(r.Context(), tenantFrom(r.Context()), r.PathValue("incidentID"), principal.ID, soc.IncidentPatch{
		Status: request.Status, Assignee: request.Assignee, Disposition: request.Disposition,
		ClosureReason: request.ClosureReason, Comment: request.Comment, Version: request.Version, RequestID: requestIDFrom(r.Context()),
	})
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	w.Header().Set("ETag", fmt.Sprintf("\"%d\"", incident.Version))
	s.json(w, http.StatusOK, incident)
}

func (s *Server) listRules(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListRules(r.Context())
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, map[string]interface{}{"items": items, "total": len(items)})
}

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	tenantID := tenantFrom(r.Context())
	items, err := s.store.ListAudit(r.Context(), tenantID, intQuery(r, "limit"))
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	chainValid, err := s.store.VerifyAudit(r.Context(), tenantID)
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, map[string]interface{}{"items": items, "total": len(items), "chain_valid": chainValid})
}

func (s *Server) resetDemo(w http.ResponseWriter, r *http.Request) {
	if s.seed == nil {
		s.problem(w, r, http.StatusNotImplemented, "seed_unavailable", "Demo reset unavailable", "No demo seed callback is configured.")
		return
	}
	if err := s.seed(r.Context()); err != nil {
		s.problem(w, r, http.StatusInternalServerError, "seed_failed", "Demo reset failed", err.Error())
		return
	}
	s.json(w, http.StatusOK, map[string]string{"status": "reset"})
}

func (s *Server) handleDomainError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.problem(w, r, http.StatusNotFound, "not_found", "Resource not found", "The resource does not exist in this tenant.")
	case errors.Is(err, store.ErrVersionConflict):
		s.problem(w, r, http.StatusPreconditionFailed, "version_conflict", "The resource changed", "Refresh the resource and retry with its current version.")
	case errors.Is(err, store.ErrAlreadyExists):
		s.problem(w, r, http.StatusConflict, "already_exists", "Resource already exists", "A resource with this identity already exists in the tenant.")
	case errors.Is(err, store.ErrAISOCIdempotencyMismatch):
		s.problem(w, r, http.StatusConflict, "ai_idempotency_mismatch", "AI request conflict", "The idempotency key was already used with a different request.")
	case errors.Is(err, aisoc.ErrInvalidRequest):
		s.problem(w, r, http.StatusUnprocessableEntity, "invalid_ai_request", "Invalid AI SOC request", err.Error())
	case errors.Is(err, aisoc.ErrInvalidPolicy):
		s.problem(w, r, http.StatusUnprocessableEntity, "invalid_ai_policy", "Invalid AI SOC policy", err.Error())
	case errors.Is(err, aisoc.ErrInvalidDecision):
		s.problem(w, r, http.StatusConflict, "invalid_ai_decision", "Invalid AI SOC decision", err.Error())
	case errors.Is(err, aisoc.ErrPolicyDisabled), errors.Is(err, aisoc.ErrCloudDisabled):
		s.problem(w, r, http.StatusConflict, "ai_policy_blocked", "AI request blocked by policy", err.Error())
	case errors.Is(err, ueba.ErrInvalidFilter):
		s.problem(w, r, http.StatusUnprocessableEntity, "invalid_ueba_filter", "Invalid UEBA filter", err.Error())
	case errors.Is(err, ueba.ErrInvalidFeedback):
		s.problem(w, r, http.StatusUnprocessableEntity, "invalid_ueba_feedback", "Invalid UEBA feedback", err.Error())
	case errors.Is(err, detection.ErrInvalidRule):
		s.problem(w, r, http.StatusBadRequest, "invalid_detection_rule", "Invalid detection rule", err.Error())
	case errors.Is(err, detection.ErrValidationFailed):
		s.problem(w, r, http.StatusUnprocessableEntity, "detection_validation_failed", "Detection validation failed", err.Error())
	case errors.Is(err, detection.ErrInvalidState):
		s.problem(w, r, http.StatusConflict, "invalid_detection_state", "Invalid detection state", err.Error())
	case errors.Is(err, hunt.ErrInvalidQuery):
		s.problem(w, r, http.StatusBadRequest, "invalid_hunt_query", "Invalid hunt query", err.Error())
	case errors.Is(err, store.ErrInvalidRetentionPolicy):
		s.problem(w, r, http.StatusUnprocessableEntity, "invalid_retention_policy", "Invalid retention policy", err.Error())
	case errors.Is(err, evidence.ErrInvalidEvidence):
		s.problem(w, r, http.StatusUnprocessableEntity, "invalid_evidence", "Invalid evidence", err.Error())
	case errors.Is(err, evidence.ErrEvidencePending), errors.Is(err, evidence.ErrIdempotencyMismatch), errors.Is(err, store.ErrEvidenceState):
		s.problem(w, r, http.StatusConflict, "evidence_conflict", "Evidence conflict", err.Error())
	case errors.Is(err, evidence.ErrEvidenceIntegrity):
		s.problem(w, r, http.StatusConflict, "evidence_integrity_failed", "Evidence integrity check failed", err.Error())
	case errors.Is(err, threatintel.ErrInvalidFeed):
		s.problem(w, r, http.StatusUnprocessableEntity, "invalid_threat_intel_feed", "Invalid threat intelligence feed", err.Error())
	case errors.Is(err, threatintel.ErrInvalidIndicator):
		s.problem(w, r, http.StatusUnprocessableEntity, "invalid_threat_indicator", "Invalid threat indicator", err.Error())
	case errors.Is(err, threatintel.ErrRetrosearchUnavailable):
		s.problem(w, r, http.StatusNotImplemented, "retrosearch_unavailable", "Retrosearch unavailable", err.Error())
	case errors.Is(err, soar.ErrInvalidPlaybook):
		s.problem(w, r, http.StatusUnprocessableEntity, "invalid_soar_playbook", "Invalid SOAR playbook", err.Error())
	case errors.Is(err, soar.ErrValidationFailed):
		s.problem(w, r, http.StatusUnprocessableEntity, "soar_validation_failed", "SOAR validation failed", err.Error())
	case errors.Is(err, soar.ErrInvalidState):
		s.problem(w, r, http.StatusConflict, "invalid_soar_state", "Invalid SOAR state", err.Error())
	case errors.Is(err, soar.ErrInvalidExecution):
		s.problem(w, r, http.StatusUnprocessableEntity, "invalid_soar_execution", "Invalid SOAR execution", err.Error())
	case errors.Is(err, soar.ErrInvalidConnector):
		s.problem(w, r, http.StatusUnprocessableEntity, "invalid_soar_connector", "Invalid SOAR connector", err.Error())
	case errors.Is(err, soc.ErrInvalidTransition):
		s.problem(w, r, http.StatusConflict, "invalid_transition", "Invalid state transition", err.Error())
	case errors.Is(err, soc.ErrClosureDetails), errors.Is(err, soc.ErrNoAlerts), errors.Is(err, pipeline.ErrInvalidEvent), errors.Is(err, ingest.ErrInvalidEnvelope):
		s.problem(w, r, http.StatusUnprocessableEntity, "validation_failed", "Validation failed", err.Error())
	default:
		s.logger.Error("request failed", "error", err, "request_id", requestIDFrom(r.Context()))
		s.problem(w, r, http.StatusInternalServerError, "internal_error", "Internal server error", "The operation could not be completed.")
	}
}

func (s *Server) json(w http.ResponseWriter, status int, value interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func (s *Server) problem(w http.ResponseWriter, r *http.Request, status int, code, title, detail string) {
	w.Header().Set("Content-Type", "application/problem+json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"type": "https://kcsp.local/problems/" + code, "title": title, "status": status,
		"detail": detail, "code": code, "trace_id": requestIDFrom(r.Context()),
	})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target interface{}) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	return decodeOne(decoder, target)
}

func decodeOne(decoder *json.Decoder, target interface{}) error {
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("request body must contain exactly one JSON value")
		}
		return err
	}
	return nil
}

func (s *Server) handleDecodeError(w http.ResponseWriter, r *http.Request, title string, err error) {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		s.problem(w, r, http.StatusRequestEntityTooLarge, "payload_too_large", "Payload too large", "The request body exceeds the 1 MiB limit.")
		return
	}
	s.problem(w, r, http.StatusBadRequest, "invalid_json", title, err.Error())
}

func intQuery(r *http.Request, key string) int {
	value, _ := strconv.Atoi(r.URL.Query().Get(key))
	return value
}

func ifMatchVersion(r *http.Request) int {
	value := strings.Trim(strings.TrimSpace(r.Header.Get("If-Match")), "\"")
	version, _ := strconv.Atoi(value)
	return version
}

func tenantFrom(ctx context.Context) string {
	value, _ := ctx.Value(tenantKey).(string)
	return value
}

func principalFrom(ctx context.Context) auth.Principal {
	value, _ := ctx.Value(principalKey).(auth.Principal)
	return value
}

func requestIDFrom(ctx context.Context) string {
	value, _ := ctx.Value(requestIDKey).(string)
	return value
}
