// Package collector implements network-facing KCSP telemetry collectors. It is
// deliberately separate from the API so untrusted device protocols terminate
// outside the SOC control plane.
package collector

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kcsp/platform/internal/agent"
	"github.com/kcsp/platform/internal/ingest"
)

type SyslogConfig struct {
	UDPAddress     string
	TCPAddress     string
	TLSAddress     string
	TLSCertificate string
	TLSPrivateKey  string
	TLSClientCA    string
	MaximumBytes   int
	EventBuffer    int
}

type SyslogReceiver struct {
	config SyslogConfig
	events chan agent.Event
	ready  chan struct{}
	once   sync.Once
}

type receiverListener struct {
	closer io.Closer
	run    func(context.Context) error
}

func NewSyslogReceiver(config SyslogConfig) (*SyslogReceiver, error) {
	config.UDPAddress = strings.TrimSpace(config.UDPAddress)
	config.TCPAddress = strings.TrimSpace(config.TCPAddress)
	config.TLSAddress = strings.TrimSpace(config.TLSAddress)
	if config.UDPAddress == "" && config.TCPAddress == "" && config.TLSAddress == "" {
		return nil, errors.New("at least one syslog UDP, TCP, or TLS listener is required")
	}
	if config.TLSAddress != "" && (config.TLSCertificate == "" || config.TLSPrivateKey == "" || config.TLSClientCA == "") {
		return nil, errors.New("syslog TLS listener requires certificate, private key, and client CA")
	}
	if config.MaximumBytes <= 0 || config.MaximumBytes > ingest.MaxEventBytes {
		config.MaximumBytes = ingest.MaxEventBytes
	}
	if config.EventBuffer <= 0 {
		config.EventBuffer = 1024
	}
	return &SyslogReceiver{config: config, events: make(chan agent.Event, config.EventBuffer), ready: make(chan struct{})}, nil
}

func (r *SyslogReceiver) Events() <-chan agent.Event { return r.events }
func (r *SyslogReceiver) Ready() <-chan struct{}     { return r.ready }

func (r *SyslogReceiver) Run(ctx context.Context) error {
	runContext, cancel := context.WithCancel(ctx)
	defer cancel()
	listeners := []receiverListener{}
	if r.config.UDPAddress != "" {
		connection, err := net.ListenPacket("udp", r.config.UDPAddress)
		if err != nil {
			return fmt.Errorf("listen for UDP syslog: %w", err)
		}
		listeners = append(listeners, receiverListener{closer: connection, run: func(runContext context.Context) error {
			return r.receiveDatagrams(runContext, connection)
		}})
	}
	if r.config.TCPAddress != "" {
		connection, err := net.Listen("tcp", r.config.TCPAddress)
		if err != nil {
			closeListeners(listeners)
			return fmt.Errorf("listen for TCP syslog: %w", err)
		}
		listeners = append(listeners, receiverListener{closer: connection, run: func(runContext context.Context) error {
			return r.receiveConnections(runContext, connection)
		}})
	}
	if r.config.TLSAddress != "" {
		tlsConfig, err := r.serverTLSConfig()
		if err != nil {
			closeListeners(listeners)
			return err
		}
		connection, err := tls.Listen("tcp", r.config.TLSAddress, tlsConfig)
		if err != nil {
			closeListeners(listeners)
			return fmt.Errorf("listen for TLS syslog: %w", err)
		}
		listeners = append(listeners, receiverListener{closer: connection, run: func(runContext context.Context) error {
			return r.receiveConnections(runContext, connection)
		}})
	}

	r.once.Do(func() { close(r.ready) })
	errorsChannel := make(chan error, len(listeners))
	var wait sync.WaitGroup
	for _, item := range listeners {
		item := item
		wait.Add(1)
		go func() {
			defer wait.Done()
			if err := item.run(runContext); err != nil && runContext.Err() == nil && !errors.Is(err, net.ErrClosed) {
				errorsChannel <- err
			}
		}()
	}
	var runErr error
	select {
	case <-ctx.Done():
		runErr = ctx.Err()
	case runErr = <-errorsChannel:
	}
	cancel()
	closeListeners(listeners)
	wait.Wait()
	return runErr
}

func closeListeners(listeners []receiverListener) {
	for _, item := range listeners {
		_ = item.closer.Close()
	}
}

func (r *SyslogReceiver) receiveDatagrams(ctx context.Context, connection net.PacketConn) error {
	buffer := make([]byte, r.config.MaximumBytes+1)
	for {
		count, remote, err := connection.ReadFrom(buffer)
		if err != nil {
			return err
		}
		if count == 0 || count > r.config.MaximumBytes {
			continue
		}
		sourceID, sourceAddress := networkSourceIdentity(remote.String())
		if err := r.emit(ctx, sourceID, sourceAddress, buffer[:count]); err != nil {
			return err
		}
	}
}

func (r *SyslogReceiver) receiveConnections(ctx context.Context, listener net.Listener) error {
	for {
		connection, err := listener.Accept()
		if err != nil {
			return err
		}
		go r.receiveStream(ctx, connection)
	}
}

func (r *SyslogReceiver) receiveStream(ctx context.Context, connection net.Conn) {
	defer connection.Close()
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = connection.Close()
		case <-done:
		}
	}()
	defer close(done)
	sourceID, sourceAddress := networkSourceIdentity(connection.RemoteAddr().String())
	if secure, ok := connection.(*tls.Conn); ok {
		if err := secure.HandshakeContext(ctx); err != nil {
			return
		}
		state := secure.ConnectionState()
		if len(state.PeerCertificates) > 0 {
			sourceID = certificateSourceIdentity(state.PeerCertificates[0])
		}
	}
	reader := bufio.NewReaderSize(connection, r.config.MaximumBytes+2)
	for {
		payload, err := readSyslogFrame(reader, r.config.MaximumBytes)
		if err != nil {
			return
		}
		if err := r.emit(ctx, sourceID, sourceAddress, payload); err != nil {
			return
		}
	}
}

func (r *SyslogReceiver) emit(ctx context.Context, sourceID, sourceAddress string, payload []byte) error {
	event, err := networkEvent(sourceID, sourceAddress, payload, time.Now().UTC())
	if err != nil {
		return nil
	}
	select {
	case r.events <- event:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func networkEvent(sourceID, sourceAddress string, payload []byte, receivedAt time.Time) (agent.Event, error) {
	payload = bytes.TrimRight(payload, "\r\n\x00")
	if len(bytes.TrimSpace(payload)) == 0 || len(payload) > ingest.MaxEventBytes {
		return agent.Event{}, errors.New("network event payload size is invalid")
	}
	format, contentType := detectFormat(payload)
	eventTimestamp := originalEventTimestamp(payload, receivedAt)
	identity := sha256.New()
	_, _ = identity.Write([]byte(sourceID))
	_, _ = identity.Write([]byte{0})
	_, _ = identity.Write([]byte(eventTimestamp.UTC().Format(time.RFC3339Nano)))
	_, _ = identity.Write([]byte{0})
	_, _ = identity.Write(payload)
	return agent.Event{
		Format: format, ContentType: contentType, EventID: "net_" + hex.EncodeToString(identity.Sum(nil)[:12]),
		EventTimestamp: eventTimestamp.UTC(), SourceID: sourceID, SourceAddress: sourceAddress,
		Payload: append([]byte(nil), payload...),
	}, nil
}

func detectFormat(payload []byte) (string, string) {
	trimmed := strings.TrimSpace(string(payload))
	switch {
	case strings.HasPrefix(trimmed, "CEF:") || strings.Index(trimmed, "CEF:") > 0 && strings.Index(trimmed, "CEF:") < 128:
		return ingest.FormatCEF, "text/plain"
	case strings.HasPrefix(trimmed, "LEEF:") || strings.Index(trimmed, "LEEF:") > 0 && strings.Index(trimmed, "LEEF:") < 128:
		return ingest.FormatLEEF, "text/plain"
	case json.Valid(payload):
		var fields map[string]json.RawMessage
		if json.Unmarshal(payload, &fields) == nil {
			if _, eventType := fields["event_type"]; eventType {
				for _, key := range []string{"src_ip", "dest_ip", "flow_id", "alert", "dns", "http", "tls"} {
					if _, fingerprint := fields[key]; fingerprint {
						return ingest.FormatSuricataEVE, "application/json"
					}
				}
			}
			if _, timestamp := fields["ts"]; timestamp {
				if _, origin := fields["id.orig_h"]; origin {
					return ingest.FormatZeekJSON, "application/json"
				}
			}
		}
		return ingest.FormatGenericJSON, "application/json"
	}
	return ingest.FormatSyslog, "text/plain"
}

func readSyslogFrame(reader *bufio.Reader, maximumBytes int) ([]byte, error) {
	first, err := reader.Peek(1)
	if err != nil {
		return nil, err
	}
	if first[0] >= '0' && first[0] <= '9' {
		var length strings.Builder
		for index := 0; index < 10; index++ {
			character, readErr := reader.ReadByte()
			if readErr != nil {
				return nil, readErr
			}
			if character == ' ' {
				if length.Len() == 0 {
					return nil, errors.New("empty RFC 6587 frame length")
				}
				count, parseErr := strconv.Atoi(length.String())
				if parseErr != nil || count <= 0 || count > maximumBytes {
					return nil, errors.New("invalid RFC 6587 frame length")
				}
				payload := make([]byte, count)
				if _, readErr = io.ReadFull(reader, payload); readErr != nil {
					return nil, readErr
				}
				return payload, nil
			}
			if character < '0' || character > '9' {
				return nil, errors.New("invalid RFC 6587 frame prefix")
			}
			length.WriteByte(character)
		}
		return nil, errors.New("RFC 6587 frame length is too long")
	}
	line, err := reader.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) || len(line) > maximumBytes+2 {
		return nil, errors.New("non-transparent syslog frame is too large")
	}
	if err != nil && !(errors.Is(err, io.EOF) && len(line) > 0) {
		return nil, err
	}
	return bytes.TrimRight(line, "\r\n"), nil
}

func networkSourceIdentity(remote string) (string, string) {
	address := strings.TrimSpace(remote)
	if host, _, err := net.SplitHostPort(address); err == nil {
		address = strings.Trim(host, "[]")
	}
	return "ip:" + address, address
}

func certificateSourceIdentity(certificate *x509.Certificate) string {
	identity := ""
	if len(certificate.URIs) > 0 {
		identity = certificate.URIs[0].String()
	} else if len(certificate.DNSNames) > 0 {
		identity = certificate.DNSNames[0]
	} else {
		identity = certificate.Subject.CommonName
	}
	identity = strings.TrimSpace(identity)
	if identity == "" || len(identity) > 220 || strings.ContainsAny(identity, "\r\n") {
		fingerprint := sha256.Sum256(certificate.Raw)
		identity = "sha256:" + hex.EncodeToString(fingerprint[:])
	}
	return "mtls:" + identity
}

func originalEventTimestamp(payload []byte, receivedAt time.Time) time.Time {
	receivedAt = receivedAt.UTC()
	trimmed := strings.TrimSpace(string(payload))
	if strings.HasPrefix(trimmed, "{") && json.Valid(payload) {
		decoder := json.NewDecoder(bytes.NewReader(payload))
		decoder.UseNumber()
		var fields map[string]interface{}
		if decoder.Decode(&fields) == nil {
			for _, key := range []string{"event_time", "timestamp", "time", "ts", "@timestamp"} {
				if parsed, ok := timestampValue(fields[key], receivedAt); ok {
					return parsed
				}
			}
		}
	}
	if marker := strings.IndexByte(trimmed, '>'); marker >= 0 && marker+1 < len(trimmed) {
		body := trimmed[marker+1:]
		fields := strings.Fields(body)
		if len(fields) >= 2 {
			if _, err := strconv.Atoi(fields[0]); err == nil {
				if parsed, ok := timestampValue(fields[1], receivedAt); ok {
					return parsed
				}
			}
		}
		if len(body) >= 15 {
			if parsed, err := time.ParseInLocation("Jan _2 15:04:05", body[:15], time.UTC); err == nil {
				parsed = time.Date(receivedAt.Year(), parsed.Month(), parsed.Day(), parsed.Hour(), parsed.Minute(), parsed.Second(), 0, time.UTC)
				if parsed.After(receivedAt.Add(24 * time.Hour)) {
					parsed = parsed.AddDate(-1, 0, 0)
				}
				return parsed
			}
		}
	}
	return receivedAt
}

func timestampValue(value interface{}, fallback time.Time) (time.Time, bool) {
	switch typed := value.(type) {
	case string:
		for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
			if parsed, err := time.Parse(layout, strings.TrimSpace(typed)); err == nil {
				return parsed.UTC(), true
			}
		}
		if numeric, err := strconv.ParseFloat(strings.TrimSpace(typed), 64); err == nil && numeric > 0 {
			return unixTelemetryTime(numeric), true
		}
	case json.Number:
		if numeric, err := typed.Float64(); err == nil && numeric > 0 {
			return unixTelemetryTime(numeric), true
		}
	case float64:
		if typed > 0 {
			return unixTelemetryTime(typed), true
		}
	}
	return fallback, false
}

func unixTelemetryTime(value float64) time.Time {
	if value > 10_000_000_000 {
		value /= 1000
	}
	seconds := int64(value)
	nanoseconds := int64((value - float64(seconds)) * float64(time.Second))
	return time.Unix(seconds, nanoseconds).UTC()
}

func (r *SyslogReceiver) serverTLSConfig() (*tls.Config, error) {
	certificate, err := tls.LoadX509KeyPair(r.config.TLSCertificate, r.config.TLSPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("load syslog TLS identity: %w", err)
	}
	caBody, err := os.ReadFile(r.config.TLSClientCA)
	if err != nil {
		return nil, fmt.Errorf("read syslog client CA: %w", err)
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(caBody) {
		return nil, errors.New("syslog client CA contains no certificates")
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate},
		ClientCAs: clientCAs, ClientAuth: tls.RequireAndVerifyClientCert,
	}, nil
}
