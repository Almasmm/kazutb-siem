package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kcsp/platform/internal/bootstrap"
	"github.com/kcsp/platform/internal/httpapi"
	"github.com/kcsp/platform/internal/pipeline"
	"github.com/kcsp/platform/internal/platform/auth"
	"github.com/kcsp/platform/internal/soc"
	"github.com/kcsp/platform/internal/store"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	memory := store.NewMemory()
	engine := pipeline.New(memory)
	socService := soc.New(memory)
	seeder := bootstrap.DemoSeeder{Store: memory, Pipeline: engine, SOC: socService}
	if err := seeder.Seed(context.Background()); err != nil {
		logger.Error("failed to seed development profile", "error", err)
		os.Exit(1)
	}

	address := os.Getenv("KCSP_LISTEN_ADDR")
	if address == "" {
		address = "127.0.0.1:8080"
	}
	handler := httpapi.New(memory, engine, socService, auth.NewDemoAuthenticator(), logger, seeder.Seed)
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

	logger.Info("KCSP API listening", "address", address, "profile", "embedded-dev", "auth", "demo-bearer")
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("server stopped unexpectedly", "error", err)
		os.Exit(1)
	}
}
