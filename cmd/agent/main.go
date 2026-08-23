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
	"github.com/kcsp/platform/internal/ingest"
)

const agentVersion = "0.4.0"

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
	serverURL := envOr("KCSP_AGENT_SERVER_URL", "https://soc.kaztbu.kz")
	tenantID := os.Getenv("KCSP_AGENT_TENANT_ID")
	accessToken := strings.TrimSpace(os.Getenv("KCSP_AGENT_ACCESS_TOKEN"))
	oauthTokenURL := strings.TrimSpace(os.Getenv("KCSP_AGENT_OAUTH_TOKEN_URL"))
	allowInsecureHTTP := strings.EqualFold(os.Getenv("KCSP_AGENT_ALLOW_INSECURE_HTTP"), "true")
	var credentialManager *agent.CredentialManager
	if accessToken == "" && oauthTokenURL == "" {
		credentialManager, err = agent.OpenCredentialManager(agent.CredentialManagerConfig{
			ServerURL: serverURL, TenantID: tenantID, EnrollmentToken: os.Getenv("KCSP_AGENT_ENROLLMENT_TOKEN"),
			StateDirectory: stateDirectory, CredentialFile: os.Getenv("KCSP_AGENT_CREDENTIAL_FILE"), IdentityFile: os.Getenv("KCSP_AGENT_IDENTITY_FILE"),
			AgentID: os.Getenv("KCSP_AGENT_ID"), AgentName: os.Getenv("KCSP_AGENT_NAME"), AgentVersion: agentVersion,
			CAFile: os.Getenv("KCSP_AGENT_CA_FILE"), CertificateFile: os.Getenv("KCSP_AGENT_CERT_FILE"), PrivateKeyFile: os.Getenv("KCSP_AGENT_KEY_FILE"),
			AllowInsecure: allowInsecureHTTP, Timeout: 30 * time.Second,
		})
		if err != nil {
			return err
		}
		bootstrapContext, cancelBootstrap := context.WithTimeout(context.Background(), 30*time.Second)
		grant, ensureErr := credentialManager.Ensure(bootstrapContext)
		cancelBootstrap()
		if ensureErr != nil {
			credentialManager.Close()
			return ensureErr
		}
		accessToken = grant.AccessToken
		defer credentialManager.Close()
	}
	newForwarder := func(token string) (*agent.Forwarder, error) {
		return agent.NewForwarder(agent.ForwarderConfig{
			ServerURL: serverURL, TenantID: tenantID, AccessToken: token, CAFile: os.Getenv("KCSP_AGENT_CA_FILE"),
			OAuthTokenURL: oauthTokenURL, OAuthClientID: os.Getenv("KCSP_AGENT_OAUTH_CLIENT_ID"),
			OAuthClientSecret: os.Getenv("KCSP_AGENT_OAUTH_CLIENT_SECRET"), OAuthScopes: strings.Fields(os.Getenv("KCSP_AGENT_OAUTH_SCOPES")),
			CertificateFile: os.Getenv("KCSP_AGENT_CERT_FILE"), PrivateKeyFile: os.Getenv("KCSP_AGENT_KEY_FILE"),
			AllowInsecureHTTP: allowInsecureHTTP, Timeout: 30 * time.Second,
		})
	}
	forwarder, err := newForwarder(accessToken)
	if err != nil {
		return err
	}
	defer func() { forwarder.Close() }()
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
	if batchSize > ingest.MaxBatchEvents {
		batchSize = ingest.MaxBatchEvents
	}
	batchMaxBytes := envInt64("KCSP_AGENT_BATCH_MAX_BYTES", 8<<20)
	if batchMaxBytes > ingest.MaxBatchRequestBytes {
		batchMaxBytes = ingest.MaxBatchRequestBytes
	}
	heartbeatInterval := envDuration("KCSP_AGENT_HEARTBEAT_INTERVAL", 30*time.Second)
	credentialRotationBefore := envDuration("KCSP_AGENT_CREDENTIAL_ROTATE_BEFORE", 24*time.Hour)
	nextCredentialRotationAttempt := time.Time{}
	nextHeartbeat := time.Time{}
	logger.Info("KCSP lightweight agent started", "version", agentVersion, "sources", sourceNames, "state_directory", stateDirectory)
	for {
		now := time.Now()
		if credentialManager != nil && now.After(nextCredentialRotationAttempt) && credentialManager.ShouldRotate(now, credentialRotationBefore) {
			rotationContext, cancelRotation := context.WithTimeout(ctx, 30*time.Second)
			grant, rotateErr := credentialManager.Rotate(rotationContext)
			cancelRotation()
			if rotateErr != nil {
				nextCredentialRotationAttempt = now.Add(5 * time.Minute)
				logger.Warn("agent credential rotation failed", "error", rotateErr, "retry_at", nextCredentialRotationAttempt)
			} else {
				replacement, replacementErr := newForwarder(grant.AccessToken)
				if replacementErr != nil {
					return replacementErr
				}
				forwarder.Close()
				forwarder = replacement
				nextCredentialRotationAttempt = time.Time{}
				logger.Info("agent credential rotated", "expires_at", grant.ExpiresAt)
			}
		}
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
		if err := flush(ctx, queue, forwarder, batchSize, batchMaxBytes); err != nil {
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

func flush(ctx context.Context, queue *agent.DiskQueue, forwarder *agent.Forwarder, batchSize int, maximumBytes int64) error {
	items, err := queue.Peek(batchSize)
	if err != nil {
		return err
	}
	selected := make([]agent.QueueItem, 0, len(items))
	events := make([]agent.Event, 0, len(items))
	var estimatedBytes int64
	for _, item := range items {
		estimate := int64(len(item.Event.Payload))*4/3 + 1024
		if estimate > maximumBytes {
			return fmt.Errorf("queued event %s exceeds configured batch byte limit", item.Event.EventID)
		}
		if len(selected) > 0 && estimatedBytes+estimate > maximumBytes {
			break
		}
		selected = append(selected, item)
		events = append(events, item.Event)
		estimatedBytes += estimate
	}
	if len(events) == 0 {
		return nil
	}
	if _, err := forwarder.SendBatch(ctx, events); err != nil {
		return err
	}
	for _, item := range selected {
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
