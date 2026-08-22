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

	"github.com/kcsp/platform/internal/soar"
	"github.com/kcsp/platform/internal/store"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(logger); err != nil {
		logger.Error("KCSP SOAR worker failed", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	startupContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	repository, err := store.OpenPostgres(startupContext, os.Getenv("KCSP_DATABASE_URL"))
	if err != nil {
		return err
	}
	defer repository.Close()
	pollInterval, err := durationEnv("KCSP_SOAR_POLL_INTERVAL", 500*time.Millisecond)
	if err != nil {
		return err
	}
	lease, err := durationEnv("KCSP_SOAR_LEASE_DURATION", 30*time.Second)
	if err != nil {
		return err
	}
	workerID := strings.TrimSpace(os.Getenv("KCSP_SOAR_WORKER_ID"))
	if workerID == "" {
		hostname, _ := os.Hostname()
		workerID = "soar-worker-" + hostname
	}
	executor := soar.NewManagedConnectorExecutor(soar.EnvironmentSecretResolver{}, nil)
	worker := soar.NewWorker(repository, nil, executor, soar.WorkerConfig{
		ID: workerID, TenantID: strings.TrimSpace(os.Getenv("KCSP_SOAR_TENANT_ID")),
		PollInterval: pollInterval, Lease: lease,
	}, logger)
	runContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	logger.Info("KCSP SOAR worker started", "worker_id", workerID, "lease", lease, "poll_interval", pollInterval)
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
