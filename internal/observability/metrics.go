package observability

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var ErrNotReady = errors.New("service is not ready")

type ReadinessCheck func(context.Context) error

type histogram struct {
	mu     sync.Mutex
	bounds []float64
	counts []uint64
	count  uint64
	sum    float64
}

func newHistogram(bounds ...float64) histogram {
	return histogram{bounds: bounds, counts: make([]uint64, len(bounds))}
}

func (h *histogram) observe(value float64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.count++
	h.sum += value
	for index, bound := range h.bounds {
		if value <= bound {
			h.counts[index]++
		}
	}
}

func (h *histogram) write(builder *strings.Builder, name, help string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	writeHelp(builder, name, help, "histogram")
	for index, bound := range h.bounds {
		fmt.Fprintf(builder, "%s_bucket{le=%q} %d\n", name, strconv.FormatFloat(bound, 'g', -1, 64), h.counts[index])
	}
	fmt.Fprintf(builder, "%s_bucket{le=\"+Inf\"} %d\n", name, h.count)
	fmt.Fprintf(builder, "%s_sum %g\n%s_count %d\n", name, h.sum, name, h.count)
}

type Registry struct {
	ready          atomic.Bool
	readinessMu    sync.RWMutex
	readinessCheck ReadinessCheck

	eventsReceived          atomic.Uint64
	eventsParsed            atomic.Uint64
	eventsFailed            atomic.Uint64
	alertsCreated           atomic.Uint64
	incidentsCreated        atomic.Uint64
	recentErrors            atomic.Uint64
	enrollmentLimited       atomic.Uint64
	enrollmentLimiterErrors atomic.Uint64
	soarApprovalApproved    atomic.Uint64
	soarApprovalRejected    atomic.Uint64
	soarApprovalDenied      atomic.Uint64
	soarApprovalConflicts   atomic.Uint64
	soarApprovalDuplicates  atomic.Uint64

	detectionLatency  histogram
	apiLatency        histogram
	clickhouseLatency histogram

	rateMu          sync.Mutex
	rateWindowStart time.Time
	rateEvents      uint64
	startedAt       time.Time
	service         string
	version         string
}

func (r *Registry) SetReadinessCheck(check ReadinessCheck) {
	r.readinessMu.Lock()
	r.readinessCheck = check
	r.readinessMu.Unlock()
}

func (r *Registry) MarkReady() {
	r.ready.Store(true)
}

func (r *Registry) MarkNotReady() {
	r.ready.Store(false)
}

func (r *Registry) Readiness(ctx context.Context) error {
	if !r.ready.Load() {
		return ErrNotReady
	}

	r.readinessMu.RLock()
	check := r.readinessCheck
	r.readinessMu.RUnlock()
	if check == nil {
		return nil
	}
	return check(ctx)
}

func SetReadinessCheck(check ReadinessCheck) {
	Default.SetReadinessCheck(check)
}

func MarkReady() {
	Default.MarkReady()
}

func MarkNotReady() {
	Default.MarkNotReady()
}

func NewRegistry(service, version string) *Registry {
	if strings.TrimSpace(service) == "" {
		service = "kcsp"
	}
	if strings.TrimSpace(version) == "" {
		version = "development"
	}
	now := time.Now()
	return &Registry{
		detectionLatency:  newHistogram(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5),
		apiLatency:        newHistogram(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5),
		clickhouseLatency: newHistogram(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5),
		rateWindowStart:   now, startedAt: now, service: service, version: version,
	}
}

var Default = NewRegistry("kcsp", "development")

func Configure(service, version string) {
	Default = NewRegistry(service, version)
}

func (r *Registry) EventReceived() {
	r.eventsReceived.Add(1)
	r.rateMu.Lock()
	now := time.Now()
	if now.Sub(r.rateWindowStart) >= 10*time.Second {
		r.rateWindowStart = now
		r.rateEvents = 0
	}
	r.rateEvents++
	r.rateMu.Unlock()
}

func (r *Registry) EventParsed()            { r.eventsParsed.Add(1) }
func (r *Registry) EventFailed()            { r.eventsFailed.Add(1); r.recentErrors.Add(1) }
func (r *Registry) AlertCreated()           { r.alertsCreated.Add(1) }
func (r *Registry) IncidentCreated()        { r.incidentsCreated.Add(1) }
func (r *Registry) EnrollmentRateLimited()  { r.enrollmentLimited.Add(1) }
func (r *Registry) EnrollmentLimiterError() { r.enrollmentLimiterErrors.Add(1); r.recentErrors.Add(1) }
func (r *Registry) SOARApprovalDecision(decision string) {
	if decision == "APPROVE" {
		r.soarApprovalApproved.Add(1)
	} else if decision == "REJECT" {
		r.soarApprovalRejected.Add(1)
	}
}
func (r *Registry) SOARApprovalFailure(class string) {
	switch class {
	case "VERSION_CONFLICT":
		r.soarApprovalConflicts.Add(1)
	case "DUPLICATE":
		r.soarApprovalDuplicates.Add(1)
	default:
		r.soarApprovalDenied.Add(1)
	}
}
func (r *Registry) ObserveDetection(value time.Duration) { r.detectionLatency.observe(value.Seconds()) }
func (r *Registry) ObserveAPI(value time.Duration)       { r.apiLatency.observe(value.Seconds()) }
func (r *Registry) ObserveClickHouse(value time.Duration) {
	r.clickhouseLatency.observe(value.Seconds())
}

func (r *Registry) ingestionEPS() float64 {
	r.rateMu.Lock()
	defer r.rateMu.Unlock()
	elapsed := time.Since(r.rateWindowStart).Seconds()
	if elapsed < 1 {
		elapsed = 1
	}
	return float64(r.rateEvents) / elapsed
}

func (r *Registry) WritePrometheus(writer io.Writer) {
	builder := &strings.Builder{}
	fmt.Fprintf(builder, "kcsp_build_info{service=%q,version=%q} 1\n", r.service, r.version)
	writeCounter(builder, "events_received_total", "Canonical events received by this process.", r.eventsReceived.Load())
	writeCounter(builder, "events_parsed_total", "Events normalized successfully by this process.", r.eventsParsed.Load())
	writeCounter(builder, "events_failed_total", "Events that failed normalization, detection, or persistence.", r.eventsFailed.Load())
	writeCounter(builder, "alerts_created_total", "New alerts created by this process.", r.alertsCreated.Load())
	writeCounter(builder, "incidents_created_total", "New incidents created by this process.", r.incidentsCreated.Load())
	writeCounter(builder, "kcsp_recent_errors_total", "Errors observed since process start.", r.recentErrors.Load())
	writeCounter(builder, "agent_enrollment_rate_limited_total", "Agent enrollment requests rejected by the shared rate limiter.", r.enrollmentLimited.Load())
	writeCounter(builder, "agent_enrollment_rate_limiter_errors_total", "Agent enrollment attempts blocked because shared rate state was unavailable.", r.enrollmentLimiterErrors.Load())
	writeCounter(builder, "soar_approval_approve_total", "Canonical APPROVE commands committed by this process.", r.soarApprovalApproved.Load())
	writeCounter(builder, "soar_approval_reject_total", "Canonical REJECT commands committed by this process.", r.soarApprovalRejected.Load())
	writeCounter(builder, "soar_approval_denied_total", "SOAR approval commands denied before commit.", r.soarApprovalDenied.Load())
	writeCounter(builder, "soar_approval_version_conflict_total", "SOAR approval commands rejected by optimistic concurrency.", r.soarApprovalConflicts.Load())
	writeCounter(builder, "soar_approval_duplicate_total", "Duplicate SOAR approval commands rejected by the action ledger.", r.soarApprovalDuplicates.Load())
	writeHelp(builder, "ingestion_eps", "Approximate events per second in the current ten-second process window.", "gauge")
	fmt.Fprintf(builder, "ingestion_eps %g\n", r.ingestionEPS())
	writeHelp(builder, "kcsp_process_uptime_seconds", "Process uptime in seconds.", "gauge")
	fmt.Fprintf(builder, "kcsp_process_uptime_seconds %g\n", time.Since(r.startedAt).Seconds())
	r.detectionLatency.write(builder, "detection_latency_seconds", "End-to-end embedded detection latency.")
	r.apiLatency.write(builder, "api_latency_seconds", "HTTP API request latency.")
	r.clickhouseLatency.write(builder, "clickhouse_query_latency_seconds", "ClickHouse operation latency.")
	_, _ = io.WriteString(writer, builder.String())
}

func writeCounter(builder *strings.Builder, name, help string, value uint64) {
	writeHelp(builder, name, help, "counter")
	fmt.Fprintf(builder, "%s %d\n", name, value)
}

func writeHelp(builder *strings.Builder, name, help, metricType string) {
	fmt.Fprintf(builder, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, metricType)
}

func HandlerFor(registry *Registry) http.Handler {
	if registry == nil {
		registry = Default
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		registry.WritePrometheus(w)
	})
	mux.HandleFunc("GET /health/live", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"status":"ok"}`)
	})
	mux.HandleFunc("GET /health/ready", func(w http.ResponseWriter, request *http.Request) {
		ctx, cancel := context.WithTimeout(request.Context(), 2*time.Second)
		defer cancel()

		w.Header().Set("Content-Type", "application/json")
		if err := registry.Readiness(ctx); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, `{"status":"not_ready"}`)
			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"status":"ready"}`)
	})
	return mux
}

func Handler() http.Handler {
	return HandlerFor(Default)
}

func Serve(ctx context.Context, address string, logger *slog.Logger) error {
	if strings.TrimSpace(address) == "" {
		return nil
	}
	server := &http.Server{
		Addr: address, Handler: Handler(), ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout: 5 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second,
	}
	stopShutdown := context.AfterFunc(ctx, func() {
		<-ctx.Done()
		shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownContext)
	})
	defer stopShutdown()
	if logger != nil {
		logger.Info("KCSP metrics endpoint started", "address", address)
	}
	err := server.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}
