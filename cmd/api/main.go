package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/kcsp/platform/internal/bootstrap"
	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/httpapi"
	"github.com/kcsp/platform/internal/ingest"
	"github.com/kcsp/platform/internal/pipeline"
	"github.com/kcsp/platform/internal/platform/auth"
	"github.com/kcsp/platform/internal/soc"
	"github.com/kcsp/platform/internal/store"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(logger); err != nil {
		logger.Error("KCSP API failed", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	profile := envOr("KCSP_PROFILE", "production")
	authMode := envOr("KCSP_AUTH_MODE", "oidc")
	if authMode == "demo" && profile != "development" && profile != "test" {
		return errors.New("demo authentication is forbidden outside development/test profiles")
	}

	startupContext, cancelStartup := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelStartup()
	repository, err := store.OpenHybrid(startupContext, os.Getenv("KCSP_DATABASE_URL"), os.Getenv("KCSP_CLICKHOUSE_URL"))
	if err != nil {
		return err
	}
	defer repository.Close()

	tenantID := envOr("KCSP_DEFAULT_TENANT_ID", core.DefaultTenantID)
	tenantName := envOr("KCSP_DEFAULT_TENANT_NAME", "K. Kulazhanov University")
	if err := repository.EnsureTenant(startupContext, tenantID, tenantName); err != nil {
		return fmt.Errorf("initialize default tenant: %w", err)
	}
	engine, err := pipeline.New(startupContext, repository)
	if err != nil {
		return err
	}
	socService := soc.New(repository)
	publisher, err := ingest.OpenKafkaPublisher(startupContext, kafkaConfig("kcsp-api"))
	if err != nil {
		return err
	}
	defer publisher.Close()
	gateway := ingest.NewGateway(publisher)
	authenticator, err := configureAuthenticator(startupContext, profile, authMode)
	if err != nil {
		return err
	}

	var seed func(context.Context) error
	if strings.EqualFold(os.Getenv("KCSP_DEMO_SEED"), "true") {
		seeder := bootstrap.DemoSeeder{Store: repository, Pipeline: engine, SOC: socService}
		if err := seeder.Seed(startupContext); err != nil {
			return fmt.Errorf("seed explicit development profile: %w", err)
		}
		seed = seeder.Seed
	}

	handler := httpapi.NewWithConfig(
		repository,
		engine,
		socService,
		authenticator,
		logger,
		seed,
		httpapi.Config{
			Profile: profile + "-distributed", AuthMode: authMode, Gateway: gateway,
			AllowDirectIngest: profile == "development" || profile == "test",
		},
	)
	address := envOr("KCSP_LISTEN_ADDR", "127.0.0.1:8080")
	server := &http.Server{
		Addr: address, Handler: handler, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second,
	}

	shutdownContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-shutdownContext.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			logger.Error("graceful shutdown failed", "error", err)
		}
	}()

	logger.Info("KCSP API listening", "address", address, "profile", profile, "auth", authMode, "store", "postgres")
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve HTTP: %w", err)
	}
	return nil
}

func kafkaConfig(clientID string) ingest.KafkaConfig {
	partitions, _ := strconv.Atoi(envOr("KCSP_KAFKA_PARTITIONS", "12"))
	replication, _ := strconv.Atoi(envOr("KCSP_KAFKA_REPLICATION_FACTOR", "1"))
	return ingest.KafkaConfig{
		Brokers: strings.Split(os.Getenv("KCSP_KAFKA_BROKERS"), ","), ClientID: clientID,
		RawTopic: os.Getenv("KCSP_KAFKA_RAW_TOPIC"), DeadLetterTopic: os.Getenv("KCSP_KAFKA_DLQ_TOPIC"),
		Partitions: int32(partitions), ReplicationFactor: int16(replication),
	}
}

func configureAuthenticator(ctx context.Context, profile, mode string) (httpapi.Authenticator, error) {
	switch mode {
	case "demo":
		if profile != "development" && profile != "test" {
			return nil, errors.New("demo authentication is forbidden outside development/test profiles")
		}
		return auth.NewDemoAuthenticator(), nil
	case "oidc":
		return auth.NewOIDCAuthenticator(ctx, auth.OIDCConfig{
			IssuerURL:       os.Getenv("KCSP_OIDC_ISSUER_URL"),
			ClientID:        os.Getenv("KCSP_OIDC_CLIENT_ID"),
			TenantClaim:     os.Getenv("KCSP_OIDC_TENANT_CLAIM"),
			RolesClaim:      os.Getenv("KCSP_OIDC_ROLES_CLAIM"),
			PermissionClaim: os.Getenv("KCSP_OIDC_PERMISSION_CLAIM"),
		})
	default:
		return nil, fmt.Errorf("unsupported KCSP_AUTH_MODE %q", mode)
	}
}

func envOr(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}
