package soar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"net/url"
	"strings"
	"time"

	"github.com/kcsp/platform/internal/core"
)

type smtpConnectorSession interface {
	Hello(string) error
	Auth(smtp.Auth) error
	Mail(string) error
	Rcpt(string) error
	Data() (io.WriteCloser, error)
	Noop() error
	Quit() error
	Close() error
}

type smtpConnectorDialer func(context.Context, core.SOARConnector, string) (smtpConnectorSession, error)

type smtpConnectorMessage struct {
	From       string
	Recipients []string
	MessageID  string
	Payload    []byte
}

func (e *ManagedConnectorExecutor) executeSMTPConnector(ctx context.Context, connector core.SOARConnector,
	request ActionRequest, secret string) (ActionResult, error) {
	message, err := buildSMTPConnectorMessage(connector, request)
	if err != nil {
		return ActionResult{}, &NodeError{Code: "connector_payload_invalid", Detail: err.Error(), Permanent: true}
	}
	session, err := e.openSMTPConnectorSession(ctx, connector, secret)
	if err != nil {
		return ActionResult{}, smtpConnectorNodeError(err)
	}
	defer session.Close()
	if err := session.Mail(message.From); err != nil {
		return ActionResult{}, smtpConnectorNodeError(err)
	}
	for _, recipient := range message.Recipients {
		if err := session.Rcpt(recipient); err != nil {
			return ActionResult{}, smtpConnectorNodeError(err)
		}
	}
	writer, err := session.Data()
	if err != nil {
		return ActionResult{}, smtpConnectorNodeError(err)
	}
	_, writeErr := writer.Write(message.Payload)
	closeErr := writer.Close()
	if writeErr != nil {
		return ActionResult{}, smtpConnectorNodeError(writeErr)
	}
	if closeErr != nil {
		return ActionResult{}, smtpConnectorNodeError(closeErr)
	}
	if err := session.Quit(); err != nil {
		return ActionResult{}, smtpConnectorNodeError(err)
	}
	return ActionResult{
		Output: map[string]interface{}{
			"connector_id": connector.ID, "message_id": message.MessageID,
			"recipients": len(message.Recipients), "accepted": true,
		},
		VerificationStatus: "ACKNOWLEDGED",
	}, nil
}

func (e *ManagedConnectorExecutor) testSMTPConnector(ctx context.Context, connector core.SOARConnector,
	secret string) ConnectorTestResult {
	started := time.Now()
	session, err := e.openSMTPConnectorSession(ctx, connector, secret)
	latency := time.Since(started).Milliseconds()
	if err != nil {
		class, detail, _ := classifySMTPConnectorError(err)
		return ConnectorTestResult{
			Status: core.SOARConnectorTestFailed, ErrorClass: class, Detail: detail, LatencyMS: latency,
		}
	}
	defer session.Close()
	if err := session.Noop(); err != nil {
		class, detail, _ := classifySMTPConnectorError(err)
		return ConnectorTestResult{
			Status: core.SOARConnectorTestFailed, ErrorClass: class, Detail: detail, LatencyMS: latency,
		}
	}
	if err := session.Quit(); err != nil {
		class, detail, _ := classifySMTPConnectorError(err)
		return ConnectorTestResult{
			Status: core.SOARConnectorTestFailed, ErrorClass: class, Detail: detail, LatencyMS: latency,
		}
	}
	return ConnectorTestResult{
		Status: core.SOARConnectorTestSucceeded, Detail: "SMTPS authentication and NOOP succeeded", LatencyMS: latency,
	}
}

func (e *ManagedConnectorExecutor) openSMTPConnectorSession(ctx context.Context,
	connector core.SOARConnector, secret string) (smtpConnectorSession, error) {
	if e.smtpDial != nil {
		return e.smtpDial(ctx, connector, secret)
	}
	return dialSMTPConnector(ctx, connector, secret)
}

func dialSMTPConnector(ctx context.Context, connector core.SOARConnector,
	secret string) (smtpConnectorSession, error) {
	endpoint, err := url.Parse(connector.Endpoint)
	if err != nil || !strings.EqualFold(endpoint.Scheme, "smtps") || endpoint.Hostname() == "" {
		return nil, errors.New("SMTPS connector endpoint is invalid")
	}
	username, password, err := connectorBasicCredentials(secret)
	if err != nil {
		return nil, err
	}
	host := endpoint.Hostname()
	port := endpoint.Port()
	if port == "" {
		port = "465"
	}
	timeout := time.Duration(connector.TimeoutSeconds) * time.Second
	if timeout <= 0 || timeout > time.Minute {
		timeout = 10 * time.Second
	}
	connection, err := dialConnectorTLS(ctx, host, port, timeout)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := connection.SetDeadline(deadline); err != nil {
		_ = connection.Close()
		return nil, err
	}
	client, err := smtp.NewClient(connection, host)
	if err != nil {
		_ = connection.Close()
		return nil, err
	}
	if helo, _ := connector.Settings["helo_name"].(string); helo != "" {
		if err := client.Hello(helo); err != nil {
			_ = client.Close()
			return nil, err
		}
	}
	if err := client.Auth(smtp.PlainAuth("", username, password, host)); err != nil {
		_ = client.Close()
		return nil, err
	}
	return client, nil
}

func dialConnectorTLS(ctx context.Context, host, port string, timeout time.Duration) (net.Conn, error) {
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, errors.New("connector host resolution failed")
	}
	foundAllowed := false
	var lastErr error
	for _, address := range addresses {
		ip := address.IP
		if ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			continue
		}
		foundAllowed = true
		dialer := &tls.Dialer{
			NetDialer: &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second},
			Config:    &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host},
		}
		connection, dialErr := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
		if dialErr == nil {
			return connection, nil
		}
		lastErr = dialErr
	}
	if !foundAllowed {
		return nil, errors.New("connector host resolves only to forbidden addresses")
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, errors.New("connector network request failed")
}

func buildSMTPConnectorMessage(connector core.SOARConnector,
	request ActionRequest) (smtpConnectorMessage, error) {
	from, _ := connector.Settings["from_address"].(string)
	fromAddress, err := mail.ParseAddress(from)
	if err != nil || fromAddress.Address == "" {
		return smtpConnectorMessage{}, fmt.Errorf("%w: SMTP from_address is invalid", ErrInvalidConnector)
	}
	toRaw, err := requiredConnectorParameter(request.Attempt.Request, "to", "recipient")
	if err != nil {
		return smtpConnectorMessage{}, err
	}
	parsedRecipients, err := mail.ParseAddressList(toRaw)
	if err != nil || len(parsedRecipients) == 0 || len(parsedRecipients) > 20 {
		return smtpConnectorMessage{}, fmt.Errorf("%w: SMTP action requires 1-20 valid recipients", ErrInvalidConnector)
	}
	recipients := make([]string, 0, len(parsedRecipients))
	for _, recipient := range parsedRecipients {
		if recipient.Address == "" || len(recipient.Address) > 320 {
			return smtpConnectorMessage{}, fmt.Errorf("%w: SMTP recipient is invalid", ErrInvalidConnector)
		}
		recipients = append(recipients, recipient.Address)
	}
	subject, err := requiredConnectorParameter(request.Attempt.Request, "subject", "title")
	if err != nil || len(subject) > 500 || strings.ContainsAny(subject, "\r\n") {
		return smtpConnectorMessage{}, fmt.Errorf("%w: SMTP subject is invalid", ErrInvalidConnector)
	}
	body, err := requiredConnectorParameter(request.Attempt.Request, "body", "text", "message")
	if err != nil {
		return smtpConnectorMessage{}, err
	}
	sum := sha256.Sum256([]byte(request.Attempt.IdempotencyKey))
	domain := "kcsp.local"
	if separator := strings.LastIndex(fromAddress.Address, "@"); separator >= 0 && separator+1 < len(fromAddress.Address) {
		domain = fromAddress.Address[separator+1:]
	}
	messageID := "<kcsp-" + hex.EncodeToString(sum[:16]) + "@" + domain + ">"
	encodedBody, err := encodeSMTPBody(body)
	if err != nil {
		return smtpConnectorMessage{}, err
	}
	headers := []string{
		"Date: " + time.Now().UTC().Format(time.RFC1123Z),
		"From: " + (&mail.Address{Address: fromAddress.Address}).String(),
		"To: " + strings.Join(recipients, ", "),
		"Subject: " + mime.QEncoding.Encode("UTF-8", subject),
		"Message-ID: " + messageID,
		"X-KCSP-Execution-ID: " + request.Attempt.ExecutionID,
		"X-KCSP-Idempotency-Key: " + request.Attempt.IdempotencyKey,
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=UTF-8",
		"Content-Transfer-Encoding: quoted-printable",
	}
	payload := []byte(strings.Join(headers, "\r\n") + "\r\n\r\n" + encodedBody)
	if len(payload) > 512<<10 {
		return smtpConnectorMessage{}, fmt.Errorf("%w: SMTP message exceeds 512 KiB", ErrInvalidConnector)
	}
	return smtpConnectorMessage{From: fromAddress.Address, Recipients: recipients, MessageID: messageID, Payload: payload}, nil
}

func encodeSMTPBody(body string) (string, error) {
	normalized := strings.ReplaceAll(strings.ReplaceAll(body, "\r\n", "\n"), "\r", "\n")
	var encoded bytes.Buffer
	writer := quotedprintable.NewWriter(&encoded)
	if _, err := writer.Write([]byte(normalized)); err != nil {
		return "", err
	}
	if err := writer.Close(); err != nil {
		return "", err
	}
	return strings.ReplaceAll(encoded.String(), "\n", "\r\n"), nil
}

func connectorBasicCredentials(secret string) (string, string, error) {
	parts := strings.SplitN(secret, ":", 2)
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || parts[1] == "" {
		return "", "", errors.New("BASIC credential must use a non-empty username:password value")
	}
	return strings.TrimSpace(parts[0]), parts[1], nil
}

func smtpConnectorNodeError(err error) *NodeError {
	class, detail, permanent := classifySMTPConnectorError(err)
	return &NodeError{Code: "connector_" + strings.ToLower(class), Detail: detail, Permanent: permanent}
}

func classifySMTPConnectorError(err error) (string, string, bool) {
	if errors.Is(err, context.DeadlineExceeded) {
		return "TIMEOUT", "SMTP connector request timed out", false
	}
	var protocolError *textproto.Error
	if errors.As(err, &protocolError) {
		switch {
		case protocolError.Code == 530 || protocolError.Code == 534 || protocolError.Code == 535:
			return "AUTHENTICATION", fmt.Sprintf("SMTP authentication failed with status %d", protocolError.Code), true
		case protocolError.Code >= 500:
			return "PROTOCOL", fmt.Sprintf("SMTP server rejected the request with status %d", protocolError.Code), true
		default:
			return "UPSTREAM", fmt.Sprintf("SMTP server deferred the request with status %d", protocolError.Code), false
		}
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return "TIMEOUT", "SMTP connector request timed out", false
	}
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "certificate") || strings.Contains(message, "tls") {
		return "TLS", "SMTP connector TLS validation failed", true
	}
	if strings.Contains(message, "forbidden addresses") {
		return "ENDPOINT_FORBIDDEN", "SMTP endpoint resolved to a forbidden address", true
	}
	if strings.Contains(message, "credential") {
		return "AUTHENTICATION", "SMTP connector credential is invalid", true
	}
	return "NETWORK", "SMTP connector network request failed", false
}
