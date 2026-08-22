package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/kcsp/platform/internal/agent"
)

const agentVersion = "0.2.0"

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
		CertificateFile: os.Getenv("KCSP_AGENT_CERT_FILE"), PrivateKeyFile: os.Getenv("KCSP_AGENT_KEY_FILE"),
		AllowInsecureHTTP: strings.EqualFold(os.Getenv("KCSP_AGENT_ALLOW_INSECURE_HTTP"), "true"), Timeout: 30 * time.Second,
	})
	if err != nil {
		return err
	}
	defer forwarder.Close()
	source, err := agent.NewSysmonSource(stateDirectory, os.Getenv("KCSP_AGENT_SYSMON_CHANNEL"))
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	pollInterval := envDuration("KCSP_AGENT_POLL_INTERVAL", 2*time.Second)
	batchSize := int(envInt64("KCSP_AGENT_BATCH_SIZE", 100))
	logger.Info("KCSP Windows agent started", "version", agentVersion, "state_directory", stateDirectory)
	for {
		if err := flush(ctx, queue, forwarder, batchSize); err != nil {
			depth, bytes, _ := queue.Depth()
			logger.Warn("KCSP gateway unavailable; events remain on disk", "error", err, "queue_depth", depth, "queue_bytes", bytes)
		}
		events, readErr := source.Read(ctx, batchSize)
		if readErr != nil {
			return readErr
		}
		persisted := 0
		for _, event := range events {
			if _, err := queue.Enqueue(event); err != nil {
				if errors.Is(err, agent.ErrQueueFull) {
					depth, bytes, _ := queue.Depth()
					logger.Warn("agent queue limit reached; source checkpoint retained", "queue_depth", depth, "queue_bytes", bytes)
					break
				}
				return err
			}
			if err := source.Commit(event.Cursor); err != nil {
				return err
			}
			persisted++
		}
		if persisted > 0 {
			logger.Info("Sysmon events persisted", "count", persisted, "last_cursor", events[persisted-1].Cursor)
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
