package store_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/enrollment"
	"github.com/kcsp/platform/internal/store"
)

func TestPostgresAgentEnrollmentConsumesSecretsAndRotatesCredential(t *testing.T) {
	databaseURL := os.Getenv("KCSP_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("KCSP_TEST_DATABASE_URL is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tenantID := strings.ReplaceAll("enrollment-"+core.NewID("tenant"), "_", "-")
	repository, err := store.OpenPostgres(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	if err := repository.EnsureTenant(ctx, tenantID, "Agent Enrollment Test"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_ = repository.ResetTenant(cleanupCtx, tenantID)
	})
	service := enrollment.NewService(repository, enrollment.Config{CredentialTTL: 24 * time.Hour, MaximumEnrollmentTTL: time.Hour})
	issued, err := service.CreateToken(ctx, tenantID, "platform-admin", enrollment.CreateTokenRequest{
		Label: "Windows pilot", CollectorType: "windows-agent", Capabilities: []string{"sysmon", "windows-event-log"}, ExpiresInSeconds: 600, MaxUses: 1,
	})
	if err != nil || issued.EnrollmentToken == "" {
		t.Fatalf("issue enrollment token: issue=%+v err=%v", issued, err)
	}
	response, err := service.Enroll(ctx, core.AgentEnrollmentRequest{
		EnrollmentToken: issued.EnrollmentToken, AgentID: "agent-dc01", Name: "Domain Controller 01",
		Hostname: "dc01.campus.local", Version: "0.4.0", Platform: "windows", Architecture: "amd64",
	}, "10.10.10.5")
	if err != nil || response.Collector.AuthSubject != "agent:agent-dc01" || response.Credential.AccessToken == "" {
		t.Fatalf("enroll agent: response=%+v err=%v", response, err)
	}
	if _, err := service.Enroll(ctx, core.AgentEnrollmentRequest{
		EnrollmentToken: issued.EnrollmentToken, AgentID: "agent-dc02", Name: "Domain Controller 02",
	}, "10.10.10.6"); !errors.Is(err, enrollment.ErrInvalidToken) {
		t.Fatalf("consumed token was accepted: %v", err)
	}
	credentialHash := sha256.Sum256([]byte(response.Credential.AccessToken))
	credential, err := repository.AgentCredentialByHash(ctx, credentialHash[:])
	if err != nil || credential.CollectorID != response.Collector.ID {
		t.Fatalf("authenticate issued credential: credential=%+v err=%v", credential, err)
	}
	replacement, err := service.RotateCredential(ctx, response.Credential.AccessToken)
	if err != nil || replacement.AccessToken == "" || replacement.AccessToken == response.Credential.AccessToken {
		t.Fatalf("rotate credential: replacement=%+v err=%v", replacement, err)
	}
	if _, err := repository.AgentCredentialByHash(ctx, credentialHash[:]); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("replaced credential remained active: %v", err)
	}
	replacementHash := sha256.Sum256([]byte(replacement.AccessToken))
	if _, err := repository.AgentCredentialByHash(ctx, replacementHash[:]); err != nil {
		t.Fatalf("replacement credential is not active: %v", err)
	}
	revocable, err := service.CreateToken(ctx, tenantID, "platform-admin", enrollment.CreateTokenRequest{
		Label: "Revocation audit", CollectorType: "linux-agent", Capabilities: []string{"journald"}, ExpiresInSeconds: 600, MaxUses: 1,
	})
	if err != nil {
		t.Fatalf("issue revocable enrollment token: %v", err)
	}
	if _, err := service.RevokeToken(ctx, tenantID, revocable.Token.ID, "security-admin"); err != nil {
		t.Fatalf("revoke enrollment token: %v", err)
	}
	auditEntries, err := repository.ListAudit(ctx, tenantID, 20)
	if err != nil {
		t.Fatalf("list enrollment audit entries: %v", err)
	}
	actions := make(map[string]int)
	for _, entry := range auditEntries {
		actions[entry.Action]++
	}
	for _, action := range []string{"agent.enrollment_token.created", "agent.enrolled", "agent.credential.rotated", "agent.enrollment_token.revoked"} {
		if actions[action] == 0 {
			t.Fatalf("missing enrollment audit action %q in %+v", action, actions)
		}
	}
	valid, err := repository.VerifyAudit(ctx, tenantID)
	if err != nil || !valid {
		t.Fatalf("enrollment audit chain verification: valid=%v err=%v", valid, err)
	}
	if _, err := repository.SetCollectorState(ctx, tenantID, response.Collector.ID, "REVOKED"); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.AgentCredentialByHash(ctx, replacementHash[:]); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("revoked collector credential was accepted: %v", err)
	}
}
