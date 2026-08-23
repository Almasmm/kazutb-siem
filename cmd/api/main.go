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

	"github.com/kcsp/platform/internal/aisoc"
	"github.com/kcsp/platform/internal/bootstrap"
	"github.com/kcsp/platform/internal/cases"
	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/detection"
	"github.com/kcsp/platform/internal/enrollment"
	"github.com/kcsp/platform/internal/entitygraph"
	"github.com/kcsp/platform/internal/ephemeral"
	"github.com/kcsp/platform/internal/evidence"
	"github.com/kcsp/platform/internal/httpapi"
	"github.com/kcsp/platform/internal/ingest"
	"github.com/kcsp/platform/internal/licensing"
	"github.com/kcsp/platform/internal/mitre"
	"github.com/kcsp/platform/internal/observability"
	"github.com/kcsp/platform/internal/parser"
	"github.com/kcsp/platform/internal/pipeline"
	"github.com/kcsp/platform/internal/platform/auth"
	"github.com/kcsp/platform/internal/reporting"
	"github.com/kcsp/platform/internal/soar"
	"github.com/kcsp/platform/internal/soc"
	"github.com/kcsp/platform/internal/store"
	"github.com/kcsp/platform/internal/threatintel"
	"github.com/kcsp/platform/internal/ueba"
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
	observability.Configure("api", envOr("KCSP_VERSION", "development"))
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
	if authMode == "demo" {
		_, err := repository.RegisterCollector(startupContext, core.Collector{
			ID: "dev-http-collector", TenantID: tenantID, Name: "Development HTTP Collector", Type: "http-json",
			AuthSubject: "svc-http-collector", Capabilities: []string{"http-json", "sysmon"}, Version: "development",
		})
		if err != nil && !errors.Is(err, store.ErrAlreadyExists) {
			return fmt.Errorf("initialize development collector binding: %w", err)
		}
	}
	engine, err := pipeline.New(startupContext, repository)
	if err != nil {
		return err
	}
	socService := soc.New(repository)
	detectionService := detection.NewService(repository)
	minioSecure, err := strconv.ParseBool(envOr("KCSP_MINIO_SECURE", "true"))
	if err != nil {
		return fmt.Errorf("parse KCSP_MINIO_SECURE: %w", err)
	}
	blobStore, err := evidence.OpenMinIOBlob(startupContext, evidence.MinIOConfig{
		Endpoint: os.Getenv("KCSP_MINIO_ENDPOINT"), AccessKey: os.Getenv("KCSP_MINIO_ACCESS_KEY"),
		SecretKey: os.Getenv("KCSP_MINIO_SECRET_KEY"), Bucket: envOr("KCSP_MINIO_EVIDENCE_BUCKET", "kcsp-evidence"),
		Region: envOr("KCSP_MINIO_REGION", "us-east-1"), Secure: minioSecure,
	})
	if err != nil {
		return err
	}
	maximumEvidenceBytes, err := strconv.ParseInt(envOr("KCSP_EVIDENCE_MAX_BYTES", strconv.FormatInt(evidence.DefaultMaximumBytes, 10)), 10, 64)
	if err != nil || maximumEvidenceBytes < 1 {
		return errors.New("KCSP_EVIDENCE_MAX_BYTES must be a positive integer")
	}
	evidenceService := evidence.NewService(repository, blobStore, evidence.Config{MaximumBytes: maximumEvidenceBytes})
	threatIntelService := threatintel.NewService(repository)
	soarService := soar.NewService(repository, nil)
	uebaService := ueba.NewService(repository)
	aiSOCService := aisoc.NewService(repository)
	caseService := cases.NewService(repository)
	entityService := entitygraph.NewService(repository)
	parserService := parser.NewStudioService(repository)
	mitreService := mitre.NewService(repository)
	reportService := reporting.NewService(repository)
	licenseKeys, err := licensing.ParseTrustedKeysJSON(os.Getenv("KCSP_LICENSE_TRUSTED_KEYS_JSON"))
	if err != nil {
		return err
	}
	licenseService := licensing.NewService(repository, licensing.Config{Profile: profile, TrustedKeys: licenseKeys})
	publisher, err := ingest.OpenKafkaPublisher(startupContext, kafkaConfig("kcsp-api"))
	if err != nil {
		return err
	}
	defer publisher.Close()
	envelopeAuthenticator, err := ingest.NewEnvelopeAuthenticator(os.Getenv("KCSP_KAFKA_ENVELOPE_HMAC_KEY"))
	if err != nil {
		return fmt.Errorf("configure Kafka envelope integrity: %w", err)
	}
	gateway := ingest.NewGateway(publisher, envelopeAuthenticator)
	primaryAuthenticator, err := configureAuthenticator(startupContext, profile, authMode)
	if err != nil {
		return err
	}
	credentialTTL, err := time.ParseDuration(envOr("KCSP_AGENT_CREDENTIAL_TTL", "720h"))
	if err != nil || credentialTTL < time.Hour {
		return errors.New("KCSP_AGENT_CREDENTIAL_TTL must be a duration of at least one hour")
	}
	maximumEnrollmentTTL, err := time.ParseDuration(envOr("KCSP_AGENT_ENROLLMENT_MAX_TTL", "168h"))
	if err != nil || maximumEnrollmentTTL < time.Minute {
		return errors.New("KCSP_AGENT_ENROLLMENT_MAX_TTL must be a duration of at least one minute")
	}
	enrollmentRatePerMinute, err := strconv.Atoi(envOr("KCSP_AGENT_ENROLLMENT_RATE_PER_MINUTE", "600"))
	if err != nil || enrollmentRatePerMinute < 1 || enrollmentRatePerMinute > 100000 {
		return errors.New("KCSP_AGENT_ENROLLMENT_RATE_PER_MINUTE must be between 1 and 100000")
	}
	secureValkey := profile != "development" && profile != "test"
	valkeyClient, err := ephemeral.OpenValkey(startupContext, ephemeral.ValkeyConfig{
		URL: os.Getenv("KCSP_VALKEY_URL"), Password: os.Getenv("KCSP_VALKEY_PASSWORD"),
		Namespace: envOr("KCSP_VALKEY_NAMESPACE", "kcsp"), RequireTLS: secureValkey, RequireAuthentication: secureValkey,
	})
	if err != nil {
		return err
	}
	defer valkeyClient.Close()
	enrollmentLimiter, err := ephemeral.NewFixedWindowLimiter(valkeyClient, ephemeral.FixedWindowConfig{
		Scope: "agent-enrollment", Limit: enrollmentRatePerMinute, Window: time.Minute,
	})
	if err != nil {
		return err
	}
	enrollmentService := enrollment.NewService(repository, enrollment.Config{
		CredentialTTL: credentialTTL, MaximumEnrollmentTTL: maximumEnrollmentTTL,
	})
	authenticator := auth.NewChainedAuthenticator(auth.NewAgentAuthenticator(repository), primaryAuthenticator)

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
			AllowDirectIngest:            profile == "development" || profile == "test",
			CollectorRegistry:            repository,
			DetectionService:             detectionService,
			HuntStore:                    repository,
			RetentionStore:               repository,
			EvidenceService:              evidenceService,
			ThreatIntelService:           threatIntelService,
			SOARService:                  soarService,
			UEBAService:                  uebaService,
			AISOCService:                 aiSOCService,
			CasesService:                 caseService,
			EntityService:                entityService,
			ParserService:                parserService,
			MITREService:                 mitreService,
			ReportService:                reportService,
			LicenseService:               licenseService,
			AgentEnrollmentService:       enrollmentService,
			AgentEnrollmentRatePerMinute: enrollmentRatePerMinute,
			AgentEnrollmentRateLimiter:   enrollmentLimiter,
			RequireRegisteredCollectors: strings.EqualFold(
				envOr("KCSP_REQUIRE_REGISTERED_COLLECTORS", strconv.FormatBool(authMode == "oidc")), "true",
			),
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
	partitions := positiveInt32Env("KCSP_KAFKA_PARTITIONS", 12)
	replication := positiveInt16Env("KCSP_KAFKA_REPLICATION_FACTOR", 1)
	return ingest.KafkaConfig{
		Brokers: strings.Split(os.Getenv("KCSP_KAFKA_BROKERS"), ","), ClientID: clientID,
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

func configureAuthenticator(ctx context.Context, profile, mode string) (httpapi.Authenticator, error) {
	switch mode {
	case "demo":
		if profile != "development" && profile != "test" {
			return nil, errors.New("demo authentication is forbidden outside development/test profiles")
		}
		return auth.NewDemoAuthenticator(), nil
	case "oidc":
		return auth.NewOIDCAuthenticator(ctx, auth.OIDCConfig{
			IssuerURL:           os.Getenv("KCSP_OIDC_ISSUER_URL"),
			ClientID:            os.Getenv("KCSP_OIDC_CLIENT_ID"),
			TenantClaim:         os.Getenv("KCSP_OIDC_TENANT_CLAIM"),
			RolesClaim:          os.Getenv("KCSP_OIDC_ROLES_CLAIM"),
			PermissionClaim:     os.Getenv("KCSP_OIDC_PERMISSION_CLAIM"),
			AllowInsecureIssuer: profile == "development" || profile == "test",
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
