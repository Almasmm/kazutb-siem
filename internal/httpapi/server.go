package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/pipeline"
	"github.com/kcsp/platform/internal/platform/auth"
	"github.com/kcsp/platform/internal/soc"
	"github.com/kcsp/platform/internal/store"
)

type contextKey string

const (
	principalKey contextKey = "principal"
	tenantKey    contextKey = "tenant"
	requestIDKey contextKey = "request-id"
)

type Server struct {
	store     store.Repository
	engine    *pipeline.Engine
	soc       *soc.Service
	auth      Authenticator
	logger    *slog.Logger
	mux       *http.ServeMux
	seed      func(context.Context) error
	startedAt time.Time
	profile   string
	authMode  string
}

type Authenticator interface {
	Authenticate(*http.Request) (auth.Principal, error)
}

type Config struct {
	Profile  string
	AuthMode string
}

func New(repository store.Repository, engine *pipeline.Engine, socService *soc.Service, authenticator Authenticator, logger *slog.Logger, seed func(context.Context) error) http.Handler {
	return NewWithConfig(repository, engine, socService, authenticator, logger, seed, Config{Profile: "test", AuthMode: "demo"})
}

func NewWithConfig(repository store.Repository, engine *pipeline.Engine, socService *soc.Service, authenticator Authenticator, logger *slog.Logger, seed func(context.Context) error, config Config) http.Handler {
	server := &Server{
		store: repository, engine: engine, soc: socService, auth: authenticator,
		logger: logger, mux: http.NewServeMux(), seed: seed, startedAt: time.Now().UTC(),
		profile: config.Profile, authMode: config.AuthMode,
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
	s.mux.Handle("POST /api/v1/events", s.protect("siem.events.ingest", http.HandlerFunc(s.ingestEvent)))
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
		tenantID := strings.TrimSpace(r.Header.Get("X-KCSP-Tenant-ID"))
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
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-KCSP-Tenant-ID, X-Request-ID, If-Match")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, OPTIONS")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		started := time.Now()
		ctx := context.WithValue(r.Context(), requestIDKey, requestID)
		next.ServeHTTP(w, r.WithContext(ctx))
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
	s.json(w, http.StatusOK, map[string]interface{}{"status": "ready", "profile": s.profile, "audit_chain_valid": auditValid})
}

func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	overview, err := s.store.Overview(r.Context(), core.DefaultTenantID)
	if err != nil {
		s.handleDomainError(w, r, err)
		return
	}
	metrics := overview["metrics"].(map[string]interface{})
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "# HELP kcsp_uptime_seconds KCSP API process uptime.\n# TYPE kcsp_uptime_seconds gauge\nkcsp_uptime_seconds %.0f\n", time.Since(s.startedAt).Seconds())
	fmt.Fprintf(w, "# HELP kcsp_events_total Events durably stored during the last 24 hours.\n# TYPE kcsp_events_total gauge\nkcsp_events_total %v\n", metrics["events_24h"])
	fmt.Fprintf(w, "# HELP kcsp_open_alerts Open alerts.\n# TYPE kcsp_open_alerts gauge\nkcsp_open_alerts %v\n", metrics["open_alerts"])
	fmt.Fprintf(w, "# HELP kcsp_active_incidents Active incidents.\n# TYPE kcsp_active_incidents gauge\nkcsp_active_incidents %v\n", metrics["active_incidents"])
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
	case errors.Is(err, soc.ErrInvalidTransition):
		s.problem(w, r, http.StatusConflict, "invalid_transition", "Invalid state transition", err.Error())
	case errors.Is(err, soc.ErrClosureDetails), errors.Is(err, soc.ErrNoAlerts), errors.Is(err, pipeline.ErrInvalidEvent):
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
