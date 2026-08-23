package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/kcsp/platform/internal/agent"
	"github.com/kcsp/platform/internal/collector"
)

const collectorVersion = "0.5.0"

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(logger); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("KCSP collector failed", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	stateDirectory := envOr("KCSP_COLLECTOR_STATE_DIR", filepath.Join(os.TempDir(), "kcsp-collector"))
	queue, err := agent.OpenDiskQueue(filepath.Join(stateDirectory, "queue"), envInt64("KCSP_COLLECTOR_QUEUE_MAX_BYTES", 10<<30))
	if err != nil {
		return err
	}
	fileSources, err := collector.ParseFileSourcesJSON(os.Getenv("KCSP_COLLECTOR_FILE_SOURCES_JSON"))
	if err != nil {
		return err
	}
	var fileTailer *collector.FileTailer
	if len(fileSources) > 0 {
		fileTailer, err = collector.NewFileTailer(collector.FileTailConfig{
			Sources: fileSources, CheckpointDirectory: filepath.Join(stateDirectory, "file-checkpoints"),
			PollInterval:        envDuration("KCSP_COLLECTOR_FILE_POLL_INTERVAL", time.Second),
			MaximumEventBytes:   int(envInt64("KCSP_COLLECTOR_MAX_EVENT_BYTES", 1<<20)),
			MaximumLinesPerPoll: int(envInt64("KCSP_COLLECTOR_FILE_MAX_LINES_PER_POLL", 1000)), Queue: queue,
		})
		if err != nil {
			return err
		}
	}
	apiSources, err := collector.ParseAPISourcesJSON(os.Getenv("KCSP_COLLECTOR_API_SOURCES_JSON"))
	if err != nil {
		return err
	}
	var apiPoller *collector.APIPoller
	if len(apiSources) > 0 {
		apiPoller, err = collector.NewAPIPoller(collector.APIPollConfig{
			Sources: apiSources, CheckpointDirectory: filepath.Join(stateDirectory, "api-checkpoints"),
			PollInterval: envDuration("KCSP_COLLECTOR_API_POLL_INTERVAL", 30*time.Second), MaximumBackoff: envDuration("KCSP_COLLECTOR_API_MAX_BACKOFF", 5*time.Minute),
			RequestTimeout: envDuration("KCSP_COLLECTOR_API_REQUEST_TIMEOUT", 30*time.Second), MaximumResponse: envInt64("KCSP_COLLECTOR_API_MAX_RESPONSE_BYTES", 16<<20),
			MaximumEventBytes: int(envInt64("KCSP_COLLECTOR_MAX_EVENT_BYTES", 1<<20)), MaximumEvents: int(envInt64("KCSP_COLLECTOR_API_MAX_EVENTS", 500)),
			MaximumPages: int(envInt64("KCSP_COLLECTOR_API_MAX_PAGES", 10)), Queue: queue, Logger: logger,
		})
		if err != nil {
			return err
		}
	}
	forwarder, err := agent.NewForwarder(agent.ForwarderConfig{
		ServerURL: envOr("KCSP_COLLECTOR_SERVER_URL", "https://soc.kaztbu.kz"), TenantID: os.Getenv("KCSP_COLLECTOR_TENANT_ID"),
		AccessToken: os.Getenv("KCSP_COLLECTOR_ACCESS_TOKEN"), CAFile: os.Getenv("KCSP_COLLECTOR_UPSTREAM_CA_FILE"),
		OAuthTokenURL: os.Getenv("KCSP_COLLECTOR_OAUTH_TOKEN_URL"), OAuthClientID: os.Getenv("KCSP_COLLECTOR_OAUTH_CLIENT_ID"),
		OAuthClientSecret: os.Getenv("KCSP_COLLECTOR_OAUTH_CLIENT_SECRET"), OAuthScopes: strings.Fields(os.Getenv("KCSP_COLLECTOR_OAUTH_SCOPES")),
		CertificateFile: os.Getenv("KCSP_COLLECTOR_UPSTREAM_CERT_FILE"), PrivateKeyFile: os.Getenv("KCSP_COLLECTOR_UPSTREAM_KEY_FILE"),
		AllowInsecureHTTP: strings.EqualFold(os.Getenv("KCSP_COLLECTOR_ALLOW_INSECURE_HTTP"), "true"), Timeout: 30 * time.Second,
	})
	if err != nil {
		return err
	}
	defer forwarder.Close()
	receiver, err := collector.NewSyslogReceiver(collector.SyslogConfig{
		UDPAddress: os.Getenv("KCSP_COLLECTOR_SYSLOG_UDP_ADDR"), TCPAddress: os.Getenv("KCSP_COLLECTOR_SYSLOG_TCP_ADDR"),
		TLSAddress: os.Getenv("KCSP_COLLECTOR_SYSLOG_TLS_ADDR"), TLSCertificate: os.Getenv("KCSP_COLLECTOR_SYSLOG_TLS_CERT_FILE"),
		TLSPrivateKey: os.Getenv("KCSP_COLLECTOR_SYSLOG_TLS_KEY_FILE"), TLSClientCA: os.Getenv("KCSP_COLLECTOR_SYSLOG_TLS_CLIENT_CA_FILE"),
		MaximumBytes: int(envInt64("KCSP_COLLECTOR_MAX_EVENT_BYTES", 1<<20)), EventBuffer: int(envInt64("KCSP_COLLECTOR_EVENT_BUFFER", 4096)),
	})
	if err != nil {
		return err
	}
	var httpReceiver *collector.HTTPReceiver
	if address := strings.TrimSpace(os.Getenv("KCSP_COLLECTOR_HTTP_ADDR")); address != "" {
		httpReceiver, err = collector.NewHTTPReceiver(collector.HTTPConfig{
			Address: address, Path: envOr("KCSP_COLLECTOR_HTTP_PATH", "/v1/events"), AccessToken: os.Getenv("KCSP_COLLECTOR_HTTP_TOKEN"),
			TLSCertificate: os.Getenv("KCSP_COLLECTOR_HTTP_TLS_CERT_FILE"), TLSPrivateKey: os.Getenv("KCSP_COLLECTOR_HTTP_TLS_KEY_FILE"),
			TLSClientCA: os.Getenv("KCSP_COLLECTOR_HTTP_TLS_CLIENT_CA_FILE"), AllowInsecureHTTP: strings.EqualFold(os.Getenv("KCSP_COLLECTOR_HTTP_ALLOW_INSECURE"), "true"),
			MaximumEventBytes: int(envInt64("KCSP_COLLECTOR_MAX_EVENT_BYTES", 1<<20)), MaximumRequest: envInt64("KCSP_COLLECTOR_HTTP_MAX_REQUEST_BYTES", 16<<20),
			MaximumBatch: int(envInt64("KCSP_COLLECTOR_HTTP_MAX_BATCH", 500)),
			Sink: func(_ context.Context, event agent.Event) error {
				_, queueErr := queue.Enqueue(event)
				return queueErr
			},
		})
		if err != nil {
			return err
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ready := &atomic.Bool{}
	healthDone := make(chan error, 1)
	go func() {
		healthDone <- serveHealth(ctx, envOr("KCSP_COLLECTOR_HEALTH_ADDR", ":8081"), queue, ready)
	}()
	receiverDone := make(chan error, 1)
	go func() { receiverDone <- receiver.Run(ctx) }()
	var httpDone <-chan error
	if httpReceiver != nil {
		done := make(chan error, 1)
		httpDone = done
		go func() { done <- httpReceiver.Run(ctx) }()
	}
	var fileDone <-chan error
	if fileTailer != nil {
		done := make(chan error, 1)
		fileDone = done
		go func() { done <- fileTailer.Run(ctx) }()
	}
	var apiDone <-chan error
	if apiPoller != nil {
		done := make(chan error, 1)
		apiDone = done
		go func() { done <- apiPoller.Run(ctx) }()
	}
	select {
	case <-receiver.Ready():
		if httpReceiver != nil {
			select {
			case <-httpReceiver.Ready():
			case httpErr := <-httpDone:
				return httpErr
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		if fileTailer != nil {
			select {
			case <-fileTailer.Ready():
			case fileErr := <-fileDone:
				return fileErr
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		if apiPoller != nil {
			select {
			case <-apiPoller.Ready():
			case apiErr := <-apiDone:
				return apiErr
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		ready.Store(true)
		logger.Info("KCSP network collector started", "version", collectorVersion, "state_directory", stateDirectory,
			"udp", os.Getenv("KCSP_COLLECTOR_SYSLOG_UDP_ADDR"), "tcp", os.Getenv("KCSP_COLLECTOR_SYSLOG_TCP_ADDR"),
			"tls", os.Getenv("KCSP_COLLECTOR_SYSLOG_TLS_ADDR"), "http", os.Getenv("KCSP_COLLECTOR_HTTP_ADDR"), "api_sources", len(apiSources))
	case runErr := <-receiverDone:
		return runErr
	case healthErr := <-healthDone:
		return healthErr
	case <-ctx.Done():
		return ctx.Err()
	}

	flushTicker := time.NewTicker(envDuration("KCSP_COLLECTOR_FLUSH_INTERVAL", 250*time.Millisecond))
	heartbeatTicker := time.NewTicker(envDuration("KCSP_COLLECTOR_HEARTBEAT_INTERVAL", 30*time.Second))
	defer flushTicker.Stop()
	defer heartbeatTicker.Stop()
	batchSize := int(envInt64("KCSP_COLLECTOR_BATCH_SIZE", 200))
	for {
		select {
		case event := <-receiver.Events():
			if _, err := queue.Enqueue(event); err != nil {
				if errors.Is(err, agent.ErrQueueFull) {
					depth, bytes, _ := queue.Depth()
					logger.Error("collector spool is full; applying source backpressure", "queue_depth", depth, "queue_bytes", bytes)
					if flushErr := flush(ctx, queue, forwarder, batchSize); flushErr != nil {
						return errors.Join(err, flushErr)
					}
					if _, retryErr := queue.Enqueue(event); retryErr != nil {
						return retryErr
					}
					continue
				}
				return err
			}
		case <-flushTicker.C:
			if err := flush(ctx, queue, forwarder, batchSize); err != nil {
				depth, bytes, _ := queue.Depth()
				logger.Warn("KCSP API unavailable; network events remain on disk", "error", err, "queue_depth", depth, "queue_bytes", bytes)
			}
		case <-heartbeatTicker.C:
			depth, bytes, _ := queue.Depth()
			if _, err := forwarder.Heartbeat(ctx, collectorVersion, map[string]interface{}{
				"os": runtime.GOOS, "arch": runtime.GOARCH, "source": "network-collector", "file_sources": len(fileSources), "api_sources": len(apiSources), "queue_depth": depth, "queue_bytes": bytes,
			}); err != nil {
				logger.Warn("collector heartbeat failed", "error", err)
			}
		case runErr := <-receiverDone:
			return runErr
		case httpErr := <-httpDone:
			return httpErr
		case fileErr := <-fileDone:
			return fileErr
		case apiErr := <-apiDone:
			return apiErr
		case healthErr := <-healthDone:
			return healthErr
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func serveHealth(ctx context.Context, address string, queue *agent.DiskQueue, ready *atomic.Bool) error {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health/live", func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(map[string]interface{}{"status": "live", "version": collectorVersion})
	})
	mux.HandleFunc("GET /health/ready", func(response http.ResponseWriter, _ *http.Request) {
		depth, bytes, err := queue.Depth()
		if err != nil || !ready.Load() {
			response.Header().Set("Content-Type", "application/problem+json")
			response.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(response).Encode(map[string]interface{}{"status": "not_ready"})
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(map[string]interface{}{"status": "ready", "queue_depth": depth, "queue_bytes": bytes})
	})
	server := &http.Server{Addr: address, Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second}
	stopShutdown := context.AfterFunc(ctx, func() {
		<-ctx.Done()
		shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownContext)
	})
	defer stopShutdown()
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func flush(ctx context.Context, queue *agent.DiskQueue, forwarder *agent.Forwarder, batchSize int) error {
	items, err := queue.Peek(batchSize)
	if err != nil {
		return err
	}
	for _, item := range items {
		if _, err := forwarder.Send(ctx, item.Event); err != nil {
			return err
		}
		if err := queue.Ack(item); err != nil {
			return err
		}
	}
	return nil
}

func envOr(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func envInt64(key string, fallback int64) int64 {
	value, err := strconv.ParseInt(strings.TrimSpace(os.Getenv(key)), 10, 64)
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}

func envDuration(key string, fallback time.Duration) time.Duration {
	value, err := time.ParseDuration(strings.TrimSpace(os.Getenv(key)))
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}
