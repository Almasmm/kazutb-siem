package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/kcsp/platform/internal/bootstrap"
	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/httpapi"
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
	if authMode != "demo" {
		return fmt.Errorf("auth mode %q is not configured yet; set KCSP_AUTH_MODE=demo only in development", authMode)
	}
	if profile != "development" && profile != "test" {
		return errors.New("demo authentication is forbidden outside development/test profiles")
	}

	startupContext, cancelStartup := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelStartup()
	repository, err := store.OpenPostgres(startupContext, os.Getenv("KCSP_DATABASE_URL"))
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
		auth.NewDemoAuthenticator(),
		logger,
		seed,
		httpapi.Config{Profile: profile + "-postgres", AuthMode: authMode},
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

func envOr(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}
