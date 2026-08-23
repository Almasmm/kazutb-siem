package soar

import (
	"bytes"
	"context"
	"io"
	"net/smtp"
	"net/textproto"
	"strings"
	"testing"

	"github.com/kcsp/platform/internal/core"
)

type recordingSMTPSession struct {
	calls []string
	data  bytes.Buffer
}

func (s *recordingSMTPSession) Hello(value string) error {
	s.calls = append(s.calls, "HELO "+value)
	return nil
}

func (s *recordingSMTPSession) Auth(smtp.Auth) error {
	s.calls = append(s.calls, "AUTH")
	return nil
}

func (s *recordingSMTPSession) Mail(value string) error {
	s.calls = append(s.calls, "MAIL "+value)
	return nil
}

func (s *recordingSMTPSession) Rcpt(value string) error {
	s.calls = append(s.calls, "RCPT "+value)
	return nil
}

func (s *recordingSMTPSession) Data() (io.WriteCloser, error) {
	s.calls = append(s.calls, "DATA")
	return recordingSMTPWriter{Writer: &s.data, close: func() { s.calls = append(s.calls, "DATA_CLOSE") }}, nil
}

func (s *recordingSMTPSession) Noop() error {
	s.calls = append(s.calls, "NOOP")
	return nil
}

func (s *recordingSMTPSession) Quit() error {
	s.calls = append(s.calls, "QUIT")
	return nil
}

func (s *recordingSMTPSession) Close() error {
	s.calls = append(s.calls, "CLOSE")
	return nil
}

type recordingSMTPWriter struct {
	io.Writer
	close func()
}

func (w recordingSMTPWriter) Close() error {
	w.close()
	return nil
}

func TestNormalizeSMTPConnectorRequiresNativeSecurityContract(t *testing.T) {
	valid := ConnectorDraft{
		Name: "University SOC email", Kind: core.SOARConnectorKindEmailSMTP,
		Endpoint: "smtps://mail.example.edu:465", AuthType: core.SOARConnectorAuthBasic,
		SecretRef: "env://KCSP_CONNECTOR_SECRET_SMTP", AllowedActions: []string{"kcsp.notification.send"},
		Settings: map[string]interface{}{"from_address": "kcsp-soc@example.edu", "helo_name": "soc.example.edu"},
	}
	connector, err := normalizeConnectorDraft(valid)
	if err != nil || connector.Kind != core.SOARConnectorKindEmailSMTP || connector.Settings["from_address"] != "kcsp-soc@example.edu" {
		t.Fatalf("valid SMTP connector rejected: connector=%+v err=%v", connector, err)
	}
	invalid := []ConnectorDraft{
		func() ConnectorDraft { item := valid; item.Endpoint = "https://mail.example.edu"; return item }(),
		func() ConnectorDraft { item := valid; item.AuthType = core.SOARConnectorAuthBearer; return item }(),
		func() ConnectorDraft { item := valid; item.Settings = map[string]interface{}{}; return item }(),
		func() ConnectorDraft {
			item := valid
			item.Endpoint = "smtps://mail.example.edu/secret-path"
			return item
		}(),
	}
	for index, draft := range invalid {
		if _, err := normalizeConnectorDraft(draft); err == nil {
			t.Fatalf("invalid SMTP connector %d was accepted", index)
		}
	}
}

func TestManagedSMTPConnectorDeliversTypedMessageOnce(t *testing.T) {
	t.Setenv("KCSP_CONNECTOR_SECRET_SMTP_TEST", "kcsp-service:mail-password")
	session := &recordingSMTPSession{}
	var resolvedSecret string
	store := &typedConnectorRuntimeStore{connector: core.SOARConnector{
		ID: "smtp-1", TenantID: "tenant-a", Kind: core.SOARConnectorKindEmailSMTP,
		State: core.SOARConnectorReady, HealthStatus: core.SOARConnectorHealthHealthy,
		Endpoint: "smtps://mail.example.edu:465", AuthType: core.SOARConnectorAuthBasic,
		SecretRef: "env://KCSP_CONNECTOR_SECRET_SMTP_TEST", AllowedActions: []string{"kcsp.notification.send"},
		Settings: map[string]interface{}{"from_address": "kcsp-soc@example.edu"}, TimeoutSeconds: 5,
		RateLimitPerMinute: 10,
	}}
	executor := NewManagedConnectorExecutor(store, EnvironmentSecretResolver{}, nil)
	executor.smtpDial = func(_ context.Context, connector core.SOARConnector, secret string) (smtpConnectorSession, error) {
		if connector.Endpoint != "smtps://mail.example.edu:465" {
			t.Fatalf("unexpected SMTP endpoint %q", connector.Endpoint)
		}
		resolvedSecret = secret
		return session, nil
	}
	request := ActionRequest{Attempt: core.SOARActionAttempt{
		TenantID: "tenant-a", ConnectorID: "smtp-1", ActionType: "kcsp.notification.send",
		RiskLevel: 2, Mode: "LIVE", IdempotencyKey: "exec-1|email", ExecutionID: "exec-1",
		Request: map[string]interface{}{
			"to": "soc@example.edu, dean@example.edu", "subject": "KCSP incident update", "body": "Incident is contained.",
		},
	}}
	result, err := executor.Execute(context.Background(), request)
	if err != nil || result.VerificationStatus != "ACKNOWLEDGED" || result.Output["recipients"] != 2 {
		t.Fatalf("SMTP connector execution failed: result=%+v err=%v", result, err)
	}
	if resolvedSecret != "kcsp-service:mail-password" || store.reservations != 1 {
		t.Fatalf("SMTP secret or quota contract failed: secret=%q reservations=%d", resolvedSecret, store.reservations)
	}
	for _, expected := range []string{"MAIL kcsp-soc@example.edu", "RCPT soc@example.edu", "RCPT dean@example.edu", "DATA", "DATA_CLOSE", "QUIT"} {
		if !containsSMTPCall(session.calls, expected) {
			t.Errorf("missing SMTP call %q: %v", expected, session.calls)
		}
	}
	message := session.data.String()
	for _, expected := range []string{"Message-ID: <kcsp-", "Subject: KCSP incident update", "X-KCSP-Execution-ID: exec-1", "Incident is contained."} {
		if !strings.Contains(message, expected) {
			t.Errorf("SMTP DATA is missing %q: %s", expected, message)
		}
	}
}

func TestManagedSMTPConnectorHealthUsesAuthenticatedNOOP(t *testing.T) {
	t.Setenv("KCSP_CONNECTOR_SECRET_SMTP_HEALTH", "kcsp-service:mail-password")
	session := &recordingSMTPSession{}
	executor := NewManagedConnectorExecutor(nil, EnvironmentSecretResolver{}, nil)
	executor.smtpDial = func(context.Context, core.SOARConnector, string) (smtpConnectorSession, error) {
		return session, nil
	}
	result, err := executor.TestConnector(context.Background(), core.SOARConnector{
		ID: "smtp-health", Kind: core.SOARConnectorKindEmailSMTP,
		State: core.SOARConnectorCredentialsNeeded, Endpoint: "smtps://mail.example.edu:465",
		AuthType: core.SOARConnectorAuthBasic, SecretRef: "env://KCSP_CONNECTOR_SECRET_SMTP_HEALTH",
		Settings: map[string]interface{}{"from_address": "kcsp-soc@example.edu"}, TimeoutSeconds: 5,
	})
	if err != nil || result.Status != core.SOARConnectorTestSucceeded || !containsSMTPCall(session.calls, "NOOP") {
		t.Fatalf("SMTP health contract failed: result=%+v calls=%v err=%v", result, session.calls, err)
	}
}

func TestSMTPErrorClassificationDoesNotExposeServerText(t *testing.T) {
	class, detail, permanent := classifySMTPConnectorError(&textproto.Error{Code: 535, Msg: "password leaked by upstream"})
	if class != "AUTHENTICATION" || !permanent || strings.Contains(detail, "password") {
		t.Fatalf("unsafe SMTP error classification: class=%s detail=%q permanent=%v", class, detail, permanent)
	}
	if _, _, err := connectorBasicCredentials("missing-separator"); err == nil {
		t.Fatal("malformed BASIC credential was accepted")
	}
}

func containsSMTPCall(calls []string, expected string) bool {
	for _, call := range calls {
		if call == expected {
			return true
		}
	}
	return false
}
