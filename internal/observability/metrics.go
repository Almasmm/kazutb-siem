package observability

import (
	"context"
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
	eventsReceived          atomic.Uint64
	eventsParsed            atomic.Uint64
	eventsFailed            atomic.Uint64
	alertsCreated           atomic.Uint64
	incidentsCreated        atomic.Uint64
	recentErrors            atomic.Uint64
	enrollmentLimited       atomic.Uint64
	enrollmentLimiterErrors atomic.Uint64

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

func (r *Registry) EventParsed()                         { r.eventsParsed.Add(1) }
func (r *Registry) EventFailed()                         { r.eventsFailed.Add(1); r.recentErrors.Add(1) }
func (r *Registry) AlertCreated()                        { r.alertsCreated.Add(1) }
func (r *Registry) IncidentCreated()                     { r.incidentsCreated.Add(1) }
func (r *Registry) EnrollmentRateLimited()               { r.enrollmentLimited.Add(1) }
func (r *Registry) EnrollmentLimiterError()              { r.enrollmentLimiterErrors.Add(1); r.recentErrors.Add(1) }
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

func Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		Default.WritePrometheus(w)
	})
	mux.HandleFunc("GET /health/live", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"status":"ok"}`)
	})
	return mux
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
