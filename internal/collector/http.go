package collector

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/kcsp/platform/internal/agent"
	"github.com/kcsp/platform/internal/ingest"
)

type HTTPSink func(context.Context, agent.Event) error

type HTTPConfig struct {
	Address           string
	Path              string
	AccessToken       string
	TLSCertificate    string
	TLSPrivateKey     string
	TLSClientCA       string
	AllowInsecureHTTP bool
	MaximumEventBytes int
	MaximumRequest    int64
	MaximumBatch      int
	Sink              HTTPSink
}

type HTTPReceiver struct {
	config HTTPConfig
	ready  chan struct{}
	once   sync.Once
}

func NewHTTPReceiver(config HTTPConfig) (*HTTPReceiver, error) {
	config.Address = strings.TrimSpace(config.Address)
	config.Path = strings.TrimSpace(config.Path)
	if config.Address == "" || config.Sink == nil {
		return nil, errors.New("HTTP collector address and persistent event sink are required")
	}
	if config.Path == "" {
		config.Path = "/v1/events"
	}
	cleanPath := path.Clean(config.Path)
	if cleanPath != config.Path || !strings.HasPrefix(config.Path, "/") {
		return nil, errors.New("HTTP collector path must be canonical and absolute")
	}
	tlsFields := 0
	for _, value := range []string{config.TLSCertificate, config.TLSPrivateKey, config.TLSClientCA} {
		if strings.TrimSpace(value) != "" {
			tlsFields++
		}
	}
	if tlsFields != 0 && tlsFields != 3 {
		return nil, errors.New("HTTP mTLS requires certificate, private key, and client CA")
	}
	if tlsFields == 0 && (!config.AllowInsecureHTTP || strings.TrimSpace(config.AccessToken) == "") {
		return nil, errors.New("plain HTTP requires an explicit development override and access token")
	}
	if config.MaximumEventBytes <= 0 || config.MaximumEventBytes > ingest.MaxEventBytes {
		config.MaximumEventBytes = ingest.MaxEventBytes
	}
	if config.MaximumRequest <= 0 || config.MaximumRequest > 64<<20 {
		config.MaximumRequest = 16 << 20
	}
	if config.MaximumBatch <= 0 || config.MaximumBatch > 5000 {
		config.MaximumBatch = 500
	}
	return &HTTPReceiver{config: config, ready: make(chan struct{})}, nil
}

func (r *HTTPReceiver) Ready() <-chan struct{} { return r.ready }

func (r *HTTPReceiver) Run(ctx context.Context) error {
	listener, err := net.Listen("tcp", r.config.Address)
	if err != nil {
		return fmt.Errorf("listen for HTTP telemetry: %w", err)
	}
	if r.config.TLSCertificate != "" {
		tlsConfig, tlsErr := loadMTLSServerConfig(r.config.TLSCertificate, r.config.TLSPrivateKey, r.config.TLSClientCA)
		if tlsErr != nil {
			_ = listener.Close()
			return tlsErr
		}
		listener = tls.NewListener(listener, tlsConfig)
	}
	server := &http.Server{
		Handler: r.handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10,
	}
	r.once.Do(func() { close(r.ready) })
	stopShutdown := context.AfterFunc(ctx, func() {
		<-ctx.Done()
		shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownContext)
	})
	defer stopShutdown()
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return ctx.Err()
}

func (r *HTTPReceiver) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+r.config.Path, r.receive)
	return mux
}

func (r *HTTPReceiver) receive(response http.ResponseWriter, request *http.Request) {
	sourceID, sourceAddress, authorized := r.sourceIdentity(request)
	if !authorized {
		writeHTTPProblem(response, http.StatusUnauthorized, "collector_authentication_failed")
		return
	}
	payloads, contentType, err := r.payloads(request)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, errHTTPRequestTooLarge) {
			status = http.StatusRequestEntityTooLarge
		}
		writeHTTPProblem(response, status, err.Error())
		return
	}
	format := strings.TrimSpace(request.Header.Get("X-KCSP-Event-Format"))
	if format != "" && !validCollectorFormat(format) {
		writeHTTPProblem(response, http.StatusBadRequest, "invalid_event_format")
		return
	}
	externalID := strings.TrimSpace(request.Header.Get("X-KCSP-Event-ID"))
	if len(payloads) != 1 {
		externalID = ""
	}
	if len(externalID) > 256 || strings.ContainsAny(externalID, "\r\n") {
		writeHTTPProblem(response, http.StatusBadRequest, "invalid_event_id")
		return
	}
	accepted := make([]string, 0, len(payloads))
	for _, payload := range payloads {
		event, eventErr := networkEvent(sourceID, sourceAddress, payload, time.Now().UTC())
		if eventErr != nil {
			writeHTTPProblem(response, http.StatusBadRequest, eventErr.Error())
			return
		}
		if format != "" {
			event.Format = format
		}
		if contentType != "" {
			event.ContentType = contentType
		}
		if externalID != "" {
			event.EventID = externalID
		}
		if sinkErr := r.config.Sink(request.Context(), event); sinkErr != nil {
			if errors.Is(sinkErr, agent.ErrQueueFull) {
				response.Header().Set("Retry-After", "1")
				writeHTTPProblem(response, http.StatusServiceUnavailable, "collector_queue_full")
				return
			}
			writeHTTPProblem(response, http.StatusInternalServerError, "collector_queue_write_failed")
			return
		}
		accepted = append(accepted, event.EventID)
	}
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(response).Encode(map[string]interface{}{"status": "PERSISTED", "accepted": len(accepted), "event_ids": accepted})
}

var errHTTPRequestTooLarge = errors.New("request_too_large")

func (r *HTTPReceiver) payloads(request *http.Request) ([][]byte, string, error) {
	body, err := io.ReadAll(io.LimitReader(request.Body, r.config.MaximumRequest+1))
	if err != nil {
		return nil, "", fmt.Errorf("read request: %w", err)
	}
	if int64(len(body)) > r.config.MaximumRequest {
		return nil, "", errHTTPRequestTooLarge
	}
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType == "" {
		mediaType = "application/json"
	}
	var payloads [][]byte
	switch mediaType {
	case "application/x-ndjson", "application/ndjson":
		for _, line := range bytes.Split(body, []byte{'\n'}) {
			line = bytes.TrimSpace(line)
			if len(line) > 0 {
				payloads = append(payloads, append([]byte(nil), line...))
			}
		}
	default:
		trimmed := bytes.TrimSpace(body)
		if len(trimmed) > 0 && trimmed[0] == '[' {
			var batch []json.RawMessage
			if err := json.Unmarshal(trimmed, &batch); err != nil {
				return nil, "", errors.New("invalid_json_batch")
			}
			for _, item := range batch {
				payloads = append(payloads, append([]byte(nil), item...))
			}
		} else if len(trimmed) > 0 {
			payloads = append(payloads, append([]byte(nil), trimmed...))
		}
	}
	if len(payloads) == 0 || len(payloads) > r.config.MaximumBatch {
		return nil, "", errors.New("invalid_batch_size")
	}
	for _, payload := range payloads {
		if len(payload) == 0 || len(payload) > r.config.MaximumEventBytes {
			return nil, "", errors.New("invalid_event_size")
		}
		if strings.Contains(mediaType, "json") {
			trimmed := bytes.TrimSpace(payload)
			if !json.Valid(trimmed) || len(trimmed) == 0 || trimmed[0] != '{' {
				return nil, "", errors.New("invalid_json_event")
			}
		}
	}
	return payloads, mediaType, nil
}

func (r *HTTPReceiver) sourceIdentity(request *http.Request) (string, string, bool) {
	networkID, address := networkSourceIdentity(request.RemoteAddr)
	authIdentity := ""
	if request.TLS != nil && len(request.TLS.PeerCertificates) > 0 {
		authIdentity = certificateSourceIdentity(request.TLS.PeerCertificates[0])
	} else {
		authorization := strings.TrimSpace(request.Header.Get("Authorization"))
		if !strings.HasPrefix(authorization, "Bearer ") {
			return "", address, false
		}
		provided := strings.TrimSpace(strings.TrimPrefix(authorization, "Bearer "))
		expected := strings.TrimSpace(r.config.AccessToken)
		if expected == "" || len(provided) != len(expected) || subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) != 1 {
			return "", address, false
		}
		digest := sha256.Sum256([]byte(expected))
		authIdentity = "token:" + hex.EncodeToString(digest[:6])
	}
	declared := strings.TrimSpace(request.Header.Get("X-KCSP-Source-ID"))
	if declared == "" {
		return authIdentity + "/" + networkID, address, true
	}
	if len(declared) > 128 || strings.ContainsAny(declared, "\r\n") {
		return "", address, false
	}
	return authIdentity + "/source:" + declared, address, true
}

func validCollectorFormat(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' || character == '_' || character == '.' {
			continue
		}
		return false
	}
	return true
}

func writeHTTPProblem(response http.ResponseWriter, status int, code string) {
	response.Header().Set("Content-Type", "application/problem+json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(map[string]interface{}{"status": status, "code": code})
}

func loadMTLSServerConfig(certificateFile, privateKeyFile, clientCAFile string) (*tls.Config, error) {
	certificate, err := tls.LoadX509KeyPair(certificateFile, privateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load collector TLS identity: %w", err)
	}
	// #nosec G304 -- certificate paths are local collector administrator configuration, never telemetry input.
	caBody, err := os.ReadFile(clientCAFile)
	if err != nil {
		return nil, fmt.Errorf("read collector client CA: %w", err)
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(caBody) {
		return nil, errors.New("collector client CA contains no certificates")
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate},
		ClientCAs: clientCAs, ClientAuth: tls.RequireAndVerifyClientCert,
	}, nil
}
