package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/ingest"
)

type ForwarderConfig struct {
	ServerURL         string
	TenantID          string
	AccessToken       string
	CAFile            string
	CertificateFile   string
	PrivateKeyFile    string
	AllowInsecureHTTP bool
	Timeout           time.Duration
}

type Forwarder struct {
	endpoint          string
	heartbeatEndpoint string
	tenantID          string
	token             string
	client            *http.Client
}

func NewForwarder(config ForwarderConfig) (*Forwarder, error) {
	serverURL, err := url.Parse(strings.TrimSpace(config.ServerURL))
	if err != nil || serverURL.Host == "" || (serverURL.Scheme != "https" && serverURL.Scheme != "http") {
		return nil, errors.New("valid KCSP http(s) server URL is required")
	}
	if serverURL.User != nil {
		return nil, errors.New("credentials must not be embedded in KCSP server URL")
	}
	if serverURL.Scheme != "https" && !config.AllowInsecureHTTP {
		return nil, errors.New("plain HTTP is disabled; configure TLS or explicit development override")
	}
	if strings.TrimSpace(config.TenantID) == "" || strings.TrimSpace(config.AccessToken) == "" {
		return nil, errors.New("tenant ID and service access token are required")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if config.CAFile != "" {
		body, readErr := os.ReadFile(config.CAFile)
		if readErr != nil {
			return nil, fmt.Errorf("read KCSP CA: %w", readErr)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(body) {
			return nil, errors.New("KCSP CA file contains no certificates")
		}
		tlsConfig.RootCAs = roots
	}
	if (config.CertificateFile == "") != (config.PrivateKeyFile == "") {
		return nil, errors.New("both mTLS certificate and private key are required")
	}
	if config.CertificateFile != "" {
		certificateFile, privateKeyFile := config.CertificateFile, config.PrivateKeyFile
		tlsConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			certificate, loadErr := tls.LoadX509KeyPair(certificateFile, privateKeyFile)
			if loadErr != nil {
				return nil, fmt.Errorf("load rotating agent certificate: %w", loadErr)
			}
			return &certificate, nil
		}
	}
	if config.Timeout <= 0 {
		config.Timeout = 30 * time.Second
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig, MaxIdleConns: 10, IdleConnTimeout: 90 * time.Second}
	baseURL := strings.TrimRight(serverURL.String(), "/")
	return &Forwarder{
		endpoint: baseURL + "/api/v1/ingest/events", heartbeatEndpoint: baseURL + "/api/v1/collectors/heartbeat",
		tenantID: config.TenantID, token: config.AccessToken,
		client: &http.Client{Transport: transport, Timeout: config.Timeout},
	}, nil
}

func (f *Forwarder) Heartbeat(ctx context.Context, version string, metadata map[string]interface{}) (core.Collector, error) {
	body, err := json.Marshal(core.CollectorHeartbeat{Version: version, Metadata: metadata})
	if err != nil {
		return core.Collector{}, fmt.Errorf("encode collector heartbeat: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, f.heartbeatEndpoint, bytes.NewReader(body))
	if err != nil {
		return core.Collector{}, fmt.Errorf("create collector heartbeat: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+f.token)
	request.Header.Set("X-KCSP-Tenant-ID", f.tenantID)
	request.Header.Set("Content-Type", "application/json")
	response, err := f.client.Do(request)
	if err != nil {
		return core.Collector{}, fmt.Errorf("send collector heartbeat: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		responseBody, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return core.Collector{}, fmt.Errorf("KCSP heartbeat returned %d: %s", response.StatusCode, strings.TrimSpace(string(responseBody)))
	}
	var collector core.Collector
	if err := json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(&collector); err != nil {
		return core.Collector{}, fmt.Errorf("decode collector heartbeat: %w", err)
	}
	return collector, nil
}

func (f *Forwarder) Send(ctx context.Context, event Event) (ingest.Receipt, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, f.endpoint, bytes.NewReader(event.Payload))
	if err != nil {
		return ingest.Receipt{}, fmt.Errorf("create ingest request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+f.token)
	request.Header.Set("X-KCSP-Tenant-ID", f.tenantID)
	request.Header.Set("X-KCSP-Event-Format", event.Format)
	request.Header.Set("X-KCSP-Event-ID", event.EventID)
	if !event.EventTimestamp.IsZero() {
		request.Header.Set("X-KCSP-Event-Timestamp", event.EventTimestamp.UTC().Format(time.RFC3339Nano))
	}
	if event.ContentType == "" {
		event.ContentType = "application/octet-stream"
	}
	request.Header.Set("Content-Type", event.ContentType)
	response, err := f.client.Do(request)
	if err != nil {
		return ingest.Receipt{}, fmt.Errorf("send event to KCSP: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return ingest.Receipt{}, fmt.Errorf("KCSP ingest returned %d: %s", response.StatusCode, strings.TrimSpace(string(body)))
	}
	var receipt ingest.Receipt
	if err := json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(&receipt); err != nil {
		return ingest.Receipt{}, fmt.Errorf("decode KCSP receipt: %w", err)
	}
	if receipt.Status != "QUEUED" || receipt.EventID != event.EventID {
		return ingest.Receipt{}, fmt.Errorf("invalid KCSP receipt for event %s", event.EventID)
	}
	return receipt, nil
}

func (f *Forwarder) Close() {
	if transport, ok := f.client.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
}
