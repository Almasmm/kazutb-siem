// Package collector implements network-facing KCSP telemetry collectors. It is
// deliberately separate from the API so untrusted device protocols terminate
// outside the SOC control plane.
package collector

import (
	"bufio"
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
		if err := r.emit(ctx, remote.String(), buffer[:count]); err != nil {
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
	scanner := bufio.NewScanner(connection)
	scanner.Buffer(make([]byte, 4096), r.config.MaximumBytes)
	for scanner.Scan() {
		if err := r.emit(ctx, connection.RemoteAddr().String(), scanner.Bytes()); err != nil {
			return
		}
	}
}

func (r *SyslogReceiver) emit(ctx context.Context, remote string, payload []byte) error {
	event, err := networkEvent(remote, payload, time.Now().UTC())
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

func networkEvent(remote string, payload []byte, receivedAt time.Time) (agent.Event, error) {
	payload = []byte(strings.TrimSpace(strings.TrimRight(string(payload), "\x00")))
	if len(payload) == 0 || len(payload) > ingest.MaxEventBytes {
		return agent.Event{}, errors.New("network event payload size is invalid")
	}
	format, contentType := detectFormat(payload)
	identity := sha256.New()
	_, _ = identity.Write([]byte(remote))
	_, _ = identity.Write([]byte{0})
	_, _ = identity.Write([]byte(receivedAt.UTC().Format(time.RFC3339Nano)))
	_, _ = identity.Write([]byte{0})
	_, _ = identity.Write(payload)
	return agent.Event{
		Format: format, ContentType: contentType, EventID: "net_" + hex.EncodeToString(identity.Sum(nil)[:12]),
		EventTimestamp: receivedAt.UTC(), Payload: append([]byte(nil), payload...),
	}, nil
}

func detectFormat(payload []byte) (string, string) {
	trimmed := strings.TrimSpace(string(payload))
	switch {
	case strings.HasPrefix(trimmed, "CEF:"):
		return ingest.FormatCEF, "text/plain"
	case strings.HasPrefix(trimmed, "LEEF:"):
		return ingest.FormatLEEF, "text/plain"
	case json.Valid(payload):
		var fields map[string]json.RawMessage
		if json.Unmarshal(payload, &fields) == nil {
			if _, ok := fields["event_type"]; ok {
				return ingest.FormatSuricataEVE, "application/json"
			}
			if _, timestamp := fields["ts"]; timestamp {
				if _, origin := fields["id.orig_h"]; origin {
					return ingest.FormatZeekJSON, "application/json"
				}
			}
		}
	}
	return ingest.FormatSyslog, "text/plain"
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
