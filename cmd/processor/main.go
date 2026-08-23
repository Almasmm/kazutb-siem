package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/ingest"
	"github.com/kcsp/platform/internal/observability"
	"github.com/kcsp/platform/internal/parser"
	"github.com/kcsp/platform/internal/pipeline"
	"github.com/kcsp/platform/internal/store"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(logger); err != nil {
		logger.Error("KCSP processor failed", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	observability.Configure("processor", envOr("KCSP_VERSION", "development"))
	startupContext, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	repository, err := store.OpenHybrid(startupContext, os.Getenv("KCSP_DATABASE_URL"), os.Getenv("KCSP_CLICKHOUSE_URL"))
	if err != nil {
		return err
	}
	defer repository.Close()
	tenantID := envOr("KCSP_DEFAULT_TENANT_ID", core.DefaultTenantID)
	if err := repository.EnsureTenant(startupContext, tenantID, envOr("KCSP_DEFAULT_TENANT_NAME", "K. Kulazhanov University")); err != nil {
		return fmt.Errorf("initialize default tenant: %w", err)
	}
	engine, err := pipeline.New(startupContext, repository)
	if err != nil {
		return err
	}
	publisher, err := ingest.OpenKafkaPublisher(startupContext, kafkaConfig())
	if err != nil {
		return err
	}
	defer publisher.Close()
	processor, err := ingest.OpenProcessor(ingest.ProcessorConfig{
		Brokers: strings.Split(os.Getenv("KCSP_KAFKA_BROKERS"), ","), ClientID: "kcsp-processor",
		GroupID: envOr("KCSP_KAFKA_CONSUMER_GROUP", "kcsp-canonical-processing-v1"), Topic: publisher.RawTopic(),
		EnvelopeHMACKey: os.Getenv("KCSP_KAFKA_ENVELOPE_HMAC_KEY"),
	}, repository, parser.NewRegistry(repository), engine, publisher)
	if err != nil {
		return err
	}
	defer processor.Close()

	runContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		if err := observability.Serve(runContext, envOr("KCSP_METRICS_ADDR", ":9090"), logger); err != nil {
			logger.Error("processor metrics endpoint failed", "error", err)
		}
	}()
	logger.Info("KCSP processor started", "group", envOr("KCSP_KAFKA_CONSUMER_GROUP", "kcsp-canonical-processing-v1"), "topic", publisher.RawTopic())
	if err := processor.Run(runContext); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

func kafkaConfig() ingest.KafkaConfig {
	partitions := positiveInt32Env("KCSP_KAFKA_PARTITIONS", 12)
	replication := positiveInt16Env("KCSP_KAFKA_REPLICATION_FACTOR", 1)
	return ingest.KafkaConfig{
		Brokers: strings.Split(os.Getenv("KCSP_KAFKA_BROKERS"), ","), ClientID: "kcsp-processor-dlq",
		RawTopic: os.Getenv("KCSP_KAFKA_RAW_TOPIC"), DeadLetterTopic: os.Getenv("KCSP_KAFKA_DLQ_TOPIC"),
		Partitions: partitions, ReplicationFactor: replication,
	}
}

func positiveInt32Env(key string, fallback int32) int32 {
	value, err := strconv.ParseInt(envOr(key, strconv.FormatInt(int64(fallback), 10)), 10, 32)
	if err != nil || value <= 0 {
		return fallback
	}
	// #nosec G115 -- ParseInt with bitSize 32 proves the value fits in int32.
	return int32(value)
}

func positiveInt16Env(key string, fallback int16) int16 {
	value, err := strconv.ParseInt(envOr(key, strconv.FormatInt(int64(fallback), 10)), 10, 16)
	if err != nil || value <= 0 {
		return fallback
	}
	// #nosec G115 -- ParseInt with bitSize 16 proves the value fits in int16.
	return int16(value)
}

func envOr(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}
