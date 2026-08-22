package store_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/soar"
	"github.com/kcsp/platform/internal/store"
)

func TestPostgresSOARConnectorLifecycleAndDurableTestQueue(t *testing.T) {
	databaseURL := os.Getenv("KCSP_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("KCSP_TEST_DATABASE_URL is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	repository, err := store.OpenPostgres(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(repository.Close)
	tenantID := "soar-connector-" + core.NewID("tenant")
	if err := repository.EnsureTenant(ctx, tenantID, "SOAR Connector Test"); err != nil {
		t.Fatal(err)
	}
	if err := repository.ResetTenant(ctx, tenantID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_ = repository.ResetTenant(cleanupCtx, tenantID)
	})
	service := soar.NewService(repository, nil)
	connector, err := service.CreateConnector(ctx, tenantID, "soar-engineer", soar.ConnectorDraft{
		Name: "University ITSM webhook", Kind: "WEBHOOK", Endpoint: "https://itsm.example.edu/kcsp",
		AuthType: "BEARER", AllowedActions: []string{"kcsp.ticket.create"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if connector.State != core.SOARConnectorCredentialsNeeded ||
		connector.HealthStatus != core.SOARConnectorHealthCredentials || connector.SecretRef != "" {
		t.Fatalf("unexpected credentials-required connector: %+v", connector)
	}
	requestID := "connector-test-" + core.NewID("request")
	first, created, err := service.QueueConnectorTest(ctx, tenantID, connector.ID, "soar-engineer", requestID)
	if err != nil || !created {
		t.Fatalf("queue connector test: created=%v test=%+v err=%v", created, first, err)
	}
	second, created, err := service.QueueConnectorTest(ctx, tenantID, connector.ID, "soar-engineer", requestID)
	if err != nil || created || second.ID != first.ID {
		t.Fatalf("connector test idempotency failed: created=%v test=%+v err=%v", created, second, err)
	}
	item, found, err := repository.ClaimSOARConnectorTest(ctx, "connector-worker", tenantID, time.Minute)
	if err != nil || !found || item.Test.ID != first.ID || item.Connector.ID != connector.ID {
		t.Fatalf("claim connector test: found=%v item=%+v err=%v", found, item, err)
	}
	finished, err := repository.FinishSOARConnectorTest(ctx, tenantID, first.ID, "connector-worker",
		core.SOARConnectorTestCredentials, "CREDENTIALS_REQUIRED", "connector has no secret binding", 0, 0)
	if err != nil || finished.Status != core.SOARConnectorTestCredentials {
		t.Fatalf("finish connector test: %+v err=%v", finished, err)
	}
	current, err := service.Connector(ctx, tenantID, connector.ID)
	if err != nil || current.State != core.SOARConnectorCredentialsNeeded ||
		current.HealthStatus != core.SOARConnectorHealthCredentials || current.Version != connector.Version+1 {
		t.Fatalf("connector health was not reconciled: %+v err=%v", current, err)
	}
	secretRef := "env://KCSP_CONNECTOR_SECRET_ITSM"
	updated, err := service.UpdateConnector(ctx, tenantID, connector.ID, "soar-engineer", soar.ConnectorPatch{
		Version: current.Version, SecretRef: &secretRef,
	})
	if err != nil || updated.SecretRef != secretRef || updated.State != core.SOARConnectorCredentialsNeeded {
		t.Fatalf("update connector secret binding: %+v err=%v", updated, err)
	}
	if _, err := service.UpdateConnector(ctx, tenantID, connector.ID, "soar-engineer", soar.ConnectorPatch{
		Version: current.Version, Name: "Stale update",
	}); !errors.Is(err, store.ErrVersionConflict) {
		t.Fatalf("stale connector update was accepted: %v", err)
	}
	if _, err := service.Connector(ctx, "another-tenant", connector.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("cross-tenant connector lookup was accepted: %v", err)
	}
}
