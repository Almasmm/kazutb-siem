package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/kcsp/platform/internal/aisoc"
	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/observability"
	"github.com/kcsp/platform/internal/store"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(logger); err != nil {
		logger.Error("KCSP AI SOC worker failed", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	observability.Configure("ai-worker", envOr("KCSP_VERSION", "development"))
	startupContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	repository, err := store.OpenHybrid(startupContext, os.Getenv("KCSP_DATABASE_URL"), os.Getenv("KCSP_CLICKHOUSE_URL"))
	if err != nil {
		return err
	}
	defer repository.Close()
	pollInterval, err := durationEnv("KCSP_AI_POLL_INTERVAL", 500*time.Millisecond)
	if err != nil {
		return err
	}
	lease, err := durationEnv("KCSP_AI_LEASE_DURATION", 90*time.Second)
	if err != nil {
		return err
	}
	workerID := strings.TrimSpace(os.Getenv("KCSP_AI_WORKER_ID"))
	if workerID == "" {
		hostname, _ := os.Hostname()
		workerID = "ai-worker-" + hostname
	}
	var local aisoc.Gateway = aisoc.NewGroundedGateway(envOr("KCSP_AI_LOCAL_MODEL", "kcsp-grounded-rules-v1"))
	if endpoint := strings.TrimSpace(os.Getenv("KCSP_AI_LOCAL_ENDPOINT")); endpoint != "" {
		local, err = aisoc.NewOpenAICompatibleGateway(aisoc.OpenAICompatibleConfig{
			Endpoint: endpoint, Model: envOr("KCSP_AI_LOCAL_MODEL", "local-security-model"),
			APIKey: os.Getenv("KCSP_AI_LOCAL_API_KEY"), Provider: core.AISOCProviderLocal,
		})
		if err != nil {
			return fmt.Errorf("configure local AI gateway: %w", err)
		}
	}
	var cloud aisoc.Gateway
	if endpoint := strings.TrimSpace(os.Getenv("KCSP_AI_CLOUD_ENDPOINT")); endpoint != "" {
		cloud, err = aisoc.NewOpenAICompatibleGateway(aisoc.OpenAICompatibleConfig{
			Endpoint: endpoint, Model: os.Getenv("KCSP_AI_CLOUD_MODEL"),
			APIKey: os.Getenv("KCSP_AI_CLOUD_API_KEY"), Provider: core.AISOCProviderCloud,
		})
		if err != nil {
			return fmt.Errorf("configure cloud AI gateway: %w", err)
		}
	}
	worker := aisoc.NewWorker(repository, local, cloud, aisoc.WorkerConfig{
		ID: workerID, TenantID: strings.TrimSpace(os.Getenv("KCSP_AI_TENANT_ID")),
		PollInterval: pollInterval, Lease: lease,
	}, logger)
	runContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		if err := observability.Serve(runContext, envOr("KCSP_METRICS_ADDR", ":9092"), logger); err != nil {
			logger.Error("AI SOC metrics endpoint failed", "error", err)
		}
	}()
	observability.SetReadinessCheck(repository.Health)
	observability.MarkReady()
	defer observability.MarkNotReady()
	logger.Info("KCSP AI SOC worker started", "worker_id", workerID, "lease", lease,
		"poll_interval", pollInterval, "cloud_configured", cloud != nil)
	return worker.Run(runContext)
}

func durationEnv(key string, fallback time.Duration) (time.Duration, error) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed <= 0 {
		return 0, fmt.Errorf("%s must be a positive Go duration", key)
	}
	return parsed, nil
}

func envOr(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}
