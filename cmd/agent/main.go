package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/kcsp/platform/internal/agent"
)

const agentVersion = "0.3.0"

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(logger); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("KCSP agent failed", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	stateDirectory := envOr("KCSP_AGENT_STATE_DIR", filepath.Join(os.TempDir(), "kcsp-agent"))
	queue, err := agent.OpenDiskQueue(filepath.Join(stateDirectory, "queue"), envInt64("KCSP_AGENT_QUEUE_MAX_BYTES", 1<<30))
	if err != nil {
		return err
	}
	forwarder, err := agent.NewForwarder(agent.ForwarderConfig{
		ServerURL: envOr("KCSP_AGENT_SERVER_URL", "https://soc.kaztbu.kz"), TenantID: os.Getenv("KCSP_AGENT_TENANT_ID"),
		AccessToken: os.Getenv("KCSP_AGENT_ACCESS_TOKEN"), CAFile: os.Getenv("KCSP_AGENT_CA_FILE"),
		OAuthTokenURL: os.Getenv("KCSP_AGENT_OAUTH_TOKEN_URL"), OAuthClientID: os.Getenv("KCSP_AGENT_OAUTH_CLIENT_ID"),
		OAuthClientSecret: os.Getenv("KCSP_AGENT_OAUTH_CLIENT_SECRET"), OAuthScopes: strings.Fields(os.Getenv("KCSP_AGENT_OAUTH_SCOPES")),
		CertificateFile: os.Getenv("KCSP_AGENT_CERT_FILE"), PrivateKeyFile: os.Getenv("KCSP_AGENT_KEY_FILE"),
		AllowInsecureHTTP: strings.EqualFold(os.Getenv("KCSP_AGENT_ALLOW_INSECURE_HTTP"), "true"), Timeout: 30 * time.Second,
	})
	if err != nil {
		return err
	}
	defer forwarder.Close()
	sources, err := telemetrySources(stateDirectory)
	if err != nil {
		return err
	}
	sourceNames := make([]string, 0, len(sources))
	for _, source := range sources {
		sourceNames = append(sourceNames, source.Name())
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	pollInterval := envDuration("KCSP_AGENT_POLL_INTERVAL", 2*time.Second)
	batchSize := int(envInt64("KCSP_AGENT_BATCH_SIZE", 100))
	heartbeatInterval := envDuration("KCSP_AGENT_HEARTBEAT_INTERVAL", 30*time.Second)
	nextHeartbeat := time.Time{}
	logger.Info("KCSP lightweight agent started", "version", agentVersion, "sources", sourceNames, "state_directory", stateDirectory)
	for {
		if time.Now().After(nextHeartbeat) {
			depth, queueBytes, _ := queue.Depth()
			if collector, heartbeatErr := forwarder.Heartbeat(ctx, agentVersion, map[string]interface{}{
				"os": runtime.GOOS, "arch": runtime.GOARCH, "sources": sourceNames, "queue_depth": depth, "queue_bytes": queueBytes,
			}); heartbeatErr != nil {
				logger.Warn("collector heartbeat failed", "error", heartbeatErr)
			} else {
				logger.Debug("collector heartbeat accepted", "collector_id", collector.ID, "health", collector.Health)
			}
			nextHeartbeat = time.Now().Add(heartbeatInterval)
		}
		if err := flush(ctx, queue, forwarder, batchSize); err != nil {
			depth, bytes, _ := queue.Depth()
			logger.Warn("KCSP gateway unavailable; events remain on disk", "error", err, "queue_depth", depth, "queue_bytes", bytes)
		}
		queueFull := false
		for _, source := range sources {
			events, readErr := source.Read(ctx, batchSize)
			if readErr != nil {
				logger.Warn("telemetry source read failed", "source", source.Name(), "error", readErr)
				continue
			}
			persisted := 0
			for _, event := range events {
				if _, err := queue.Enqueue(event); err != nil {
					if errors.Is(err, agent.ErrQueueFull) {
						depth, bytes, _ := queue.Depth()
						logger.Warn("agent queue limit reached; source checkpoint retained", "source", source.Name(), "queue_depth", depth, "queue_bytes", bytes)
						queueFull = true
						break
					}
					return err
				}
				if err := source.CommitEvent(event); err != nil {
					return err
				}
				persisted++
			}
			if persisted > 0 {
				last := events[persisted-1]
				logger.Info("agent events persisted", "source", source.Name(), "count", persisted, "last_cursor", last.Cursor, "last_checkpoint", last.Checkpoint)
			}
			if queueFull {
				break
			}
		}
		timer := time.NewTimer(pollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func telemetrySources(stateDirectory string) ([]agent.TelemetrySource, error) {
	name := strings.ToLower(strings.TrimSpace(os.Getenv("KCSP_AGENT_SOURCE")))
	if name == "" || name == "auto" {
		switch runtime.GOOS {
		case "windows":
			sources := make([]agent.TelemetrySource, 0, 1+len(windowsEventChannels()))
			sysmon, err := agent.NewSysmonSource(stateDirectory, os.Getenv("KCSP_AGENT_SYSMON_CHANNEL"))
			if err != nil {
				return nil, err
			}
			sources = append(sources, sysmon)
			for _, channel := range windowsEventChannels() {
				source, err := agent.NewWindowsEventSource(stateDirectory, channel)
				if err != nil {
					return nil, err
				}
				sources = append(sources, source)
			}
			return sources, nil
		case "linux":
			name = "journald"
		default:
			return nil, fmt.Errorf("automatic telemetry source is not supported on %s", runtime.GOOS)
		}
	}
	switch name {
	case "sysmon":
		source, err := agent.NewSysmonSource(stateDirectory, os.Getenv("KCSP_AGENT_SYSMON_CHANNEL"))
		return singleSource(source, err)
	case "journald":
		source, err := agent.NewJournalSource(stateDirectory, strings.Fields(os.Getenv("KCSP_AGENT_JOURNAL_MATCHES")))
		return singleSource(source, err)
	case "windows-event-log":
		sources := make([]agent.TelemetrySource, 0, len(windowsEventChannels()))
		for _, channel := range windowsEventChannels() {
			source, err := agent.NewWindowsEventSource(stateDirectory, channel)
			if err != nil {
				return nil, err
			}
			sources = append(sources, source)
		}
		return sources, nil
	default:
		return nil, fmt.Errorf("unsupported KCSP_AGENT_SOURCE %q", name)
	}
}

func singleSource(source agent.TelemetrySource, err error) ([]agent.TelemetrySource, error) {
	if err != nil {
		return nil, err
	}
	return []agent.TelemetrySource{source}, nil
}

func windowsEventChannels() []string {
	configured := strings.TrimSpace(os.Getenv("KCSP_AGENT_WINDOWS_CHANNELS"))
	if configured == "" {
		return []string{"Security", "System", "Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-Windows Defender/Operational"}
	}
	channels := make([]string, 0)
	seen := make(map[string]struct{})
	for _, channel := range strings.Split(configured, ";") {
		channel = strings.TrimSpace(channel)
		key := strings.ToLower(channel)
		if channel == "" {
			continue
		}
		if _, found := seen[key]; found {
			continue
		}
		seen[key] = struct{}{}
		channels = append(channels, channel)
	}
	if len(channels) == 0 {
		return []string{"Security"}
	}
	return channels
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
