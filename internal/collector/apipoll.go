package collector

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kcsp/platform/internal/agent"
	"github.com/kcsp/platform/internal/ingest"
)

type APISource struct {
	SourceID               string `json:"source_id"`
	URL                    string `json:"url"`
	Format                 string `json:"format,omitempty"`
	EventsPath             string `json:"events_path,omitempty"`
	EventIDPath            string `json:"event_id_path,omitempty"`
	CursorPath             string `json:"cursor_path,omitempty"`
	HasMorePath            string `json:"has_more_path,omitempty"`
	CursorQueryParameter   string `json:"cursor_query_parameter,omitempty"`
	PageSizeQueryParameter string `json:"page_size_query_parameter,omitempty"`
	PageSize               int    `json:"page_size,omitempty"`
	IntervalSeconds        int    `json:"interval_seconds,omitempty"`
	AuthType               string `json:"auth_type,omitempty"`
	SecretEnv              string `json:"secret_env,omitempty"`
	APIKeyHeader           string `json:"api_key_header,omitempty"`
	CAFile                 string `json:"ca_file,omitempty"`
	CertificateFile        string `json:"certificate_file,omitempty"`
	PrivateKeyFile         string `json:"private_key_file,omitempty"`
}

type APIPollConfig struct {
	Sources             []APISource
	CheckpointDirectory string
	PollInterval        time.Duration
	MaximumBackoff      time.Duration
	RequestTimeout      time.Duration
	MaximumResponse     int64
	MaximumEventBytes   int
	MaximumEvents       int
	MaximumPages        int
	Queue               *agent.DiskQueue
	Logger              *slog.Logger
}

type APIPoller struct {
	config  APIPollConfig
	sources []apiSourceRuntime
	ready   chan struct{}
	once    sync.Once
}

type apiSourceRuntime struct {
	source      APISource
	client      *http.Client
	secret      string
	cursor      string
	nextAttempt time.Time
	failures    int
}

type apiCheckpoint struct {
	SourceID  string    `json:"source_id"`
	URL       string    `json:"url"`
	Cursor    string    `json:"cursor"`
	UpdatedAt time.Time `json:"updated_at"`
}

type apiPage struct {
	events     []map[string]interface{}
	nextCursor string
	hasMore    bool
}

type apiResponseError struct {
	status     int
	retryAfter time.Duration
}

func (e *apiResponseError) Error() string {
	return fmt.Sprintf("API source returned HTTP %d", e.status)
}

func ParseAPISourcesJSON(value string) ([]APISource, error) {
	value = strings.TrimSpace(value)
	if value == "" || value == "[]" {
		return nil, nil
	}
	decoder := json.NewDecoder(strings.NewReader(value))
	decoder.DisallowUnknownFields()
	var sources []APISource
	if err := decoder.Decode(&sources); err != nil {
		return nil, fmt.Errorf("decode KCSP_COLLECTOR_API_SOURCES_JSON: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("KCSP_COLLECTOR_API_SOURCES_JSON contains trailing data")
	}
	if len(sources) > 64 {
		return nil, errors.New("at most 64 API sources are allowed per collector")
	}
	return sources, nil
}

func NewAPIPoller(config APIPollConfig) (*APIPoller, error) {
	if len(config.Sources) == 0 || config.Queue == nil {
		return nil, errors.New("API sources and persistent queue are required")
	}
	config.CheckpointDirectory = strings.TrimSpace(config.CheckpointDirectory)
	if config.CheckpointDirectory == "" {
		return nil, errors.New("API checkpoint directory is required")
	}
	if config.PollInterval <= 0 {
		config.PollInterval = 30 * time.Second
	}
	if config.MaximumBackoff < config.PollInterval {
		config.MaximumBackoff = 5 * time.Minute
	}
	if config.RequestTimeout <= 0 || config.RequestTimeout > 5*time.Minute {
		config.RequestTimeout = 30 * time.Second
	}
	if config.MaximumResponse <= 0 || config.MaximumResponse > 64<<20 {
		config.MaximumResponse = 16 << 20
	}
	if config.MaximumEventBytes <= 0 || config.MaximumEventBytes > ingest.MaxEventBytes {
		config.MaximumEventBytes = ingest.MaxEventBytes
	}
	if config.MaximumEvents <= 0 || config.MaximumEvents > 5000 {
		config.MaximumEvents = 500
	}
	if config.MaximumPages <= 0 || config.MaximumPages > 100 {
		config.MaximumPages = 10
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	if err := os.MkdirAll(config.CheckpointDirectory, 0o700); err != nil {
		return nil, fmt.Errorf("create API checkpoint directory: %w", err)
	}
	poller := &APIPoller{config: config, ready: make(chan struct{})}
	seen := map[string]bool{}
	for index := range config.Sources {
		source, err := normalizeAPISource(config.Sources[index])
		if err != nil {
			return nil, fmt.Errorf("invalid API source %d: %w", index, err)
		}
		if seen[source.SourceID] {
			return nil, fmt.Errorf("duplicate API source_id %q", source.SourceID)
		}
		seen[source.SourceID] = true
		client, secret, err := apiHTTPClient(source, config.RequestTimeout)
		if err != nil {
			return nil, fmt.Errorf("configure API source %q: %w", source.SourceID, err)
		}
		checkpoint, found, err := loadAPICheckpoint(config.CheckpointDirectory, source)
		if err != nil {
			return nil, err
		}
		runtime := apiSourceRuntime{source: source, client: client, secret: secret}
		if found {
			runtime.cursor = checkpoint.Cursor
		}
		poller.sources = append(poller.sources, runtime)
	}
	return poller, nil
}

func (p *APIPoller) Ready() <-chan struct{} { return p.ready }

func (p *APIPoller) Run(ctx context.Context) error {
	p.once.Do(func() { close(p.ready) })
	for {
		now := time.Now()
		nextWake := now.Add(p.config.MaximumBackoff)
		for index := range p.sources {
			source := &p.sources[index]
			if source.nextAttempt.After(now) {
				if source.nextAttempt.Before(nextWake) {
					nextWake = source.nextAttempt
				}
				continue
			}
			err := p.pollSource(ctx, source)
			if ctx.Err() != nil {
				return ctx.Err()
			}
			delay := p.sourceInterval(source.source)
			if err != nil {
				source.failures++
				delay = p.retryDelay(source.failures, err)
				p.config.Logger.Warn("API telemetry poll failed; cursor was not advanced", "source_id", source.source.SourceID, "error", err, "retry_in", delay)
			} else {
				source.failures = 0
			}
			source.nextAttempt = time.Now().Add(delay)
			if source.nextAttempt.Before(nextWake) {
				nextWake = source.nextAttempt
			}
		}
		wait := time.Until(nextWake)
		if wait < 10*time.Millisecond {
			wait = 10 * time.Millisecond
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (p *APIPoller) pollSource(ctx context.Context, runtime *apiSourceRuntime) error {
	cursor := runtime.cursor
	for pageNumber := 0; pageNumber < p.config.MaximumPages; pageNumber++ {
		page, err := p.fetchPage(ctx, runtime, cursor)
		if err != nil {
			return err
		}
		if len(page.events) > 0 && (page.nextCursor == "" || page.nextCursor == cursor) {
			return errors.New("API response with events must advance the cursor")
		}
		for index, document := range page.events {
			payload, err := json.Marshal(document)
			if err != nil {
				return fmt.Errorf("encode API event: %w", err)
			}
			if len(payload) == 0 || len(payload) > p.config.MaximumEventBytes {
				return fmt.Errorf("API event exceeds %d bytes", p.config.MaximumEventBytes)
			}
			event, err := networkEvent(runtime.source.SourceID, sanitizedAPIAddress(runtime.source.URL), payload, time.Now().UTC())
			if err != nil {
				return err
			}
			event.Format = runtime.source.Format
			event.ContentType = "application/json"
			event.EventID = stableAPIEventID(runtime.source, document, cursor, index, payload)
			event.Checkpoint = page.nextCursor
			if _, err := p.config.Queue.EnqueueUnique(event); err != nil {
				return err
			}
		}
		if page.nextCursor != "" && page.nextCursor != cursor {
			if err := commitAPICheckpoint(p.config.CheckpointDirectory, runtime.source, page.nextCursor); err != nil {
				return err
			}
			cursor = page.nextCursor
			runtime.cursor = cursor
		}
		if !page.hasMore {
			return nil
		}
		if page.nextCursor == "" || page.nextCursor == runtime.cursor && len(page.events) == 0 {
			return errors.New("paginated API response did not advance the cursor")
		}
	}
	return fmt.Errorf("API source exceeded %d pages in one poll", p.config.MaximumPages)
}

func (p *APIPoller) fetchPage(ctx context.Context, runtime *apiSourceRuntime, cursor string) (apiPage, error) {
	endpoint, err := url.Parse(runtime.source.URL)
	if err != nil {
		return apiPage{}, err
	}
	query := endpoint.Query()
	if cursor != "" {
		query.Set(runtime.source.CursorQueryParameter, cursor)
	} else {
		query.Del(runtime.source.CursorQueryParameter)
	}
	query.Set(runtime.source.PageSizeQueryParameter, strconv.Itoa(runtime.source.PageSize))
	endpoint.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return apiPage{}, fmt.Errorf("build API request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "KCSP-Collector/0.5")
	switch runtime.source.AuthType {
	case "BEARER":
		request.Header.Set("Authorization", "Bearer "+runtime.secret)
	case "API_KEY":
		request.Header.Set(runtime.source.APIKeyHeader, runtime.secret)
	}
	response, err := runtime.client.Do(request)
	if err != nil {
		return apiPage{}, fmt.Errorf("request API source: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4<<10))
		return apiPage{}, &apiResponseError{status: response.StatusCode, retryAfter: parseRetryAfter(response.Header.Get("Retry-After"))}
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, p.config.MaximumResponse+1))
	if err != nil {
		return apiPage{}, fmt.Errorf("read API response: %w", err)
	}
	if int64(len(body)) > p.config.MaximumResponse {
		return apiPage{}, errors.New("API response exceeds configured byte limit")
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.UseNumber()
	var document interface{}
	if err := decoder.Decode(&document); err != nil {
		return apiPage{}, errors.New("API response is not valid JSON")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return apiPage{}, errors.New("API response contains trailing data")
	}
	eventsValue, found := jsonPathValue(document, runtime.source.EventsPath)
	if !found {
		return apiPage{}, fmt.Errorf("API response is missing events_path %q", runtime.source.EventsPath)
	}
	rawEvents, ok := eventsValue.([]interface{})
	if !ok || len(rawEvents) > p.config.MaximumEvents {
		return apiPage{}, errors.New("API events_path must be an array within the configured event limit")
	}
	page := apiPage{events: make([]map[string]interface{}, 0, len(rawEvents))}
	for _, raw := range rawEvents {
		event, ok := raw.(map[string]interface{})
		if !ok {
			return apiPage{}, errors.New("API events must be JSON objects")
		}
		page.events = append(page.events, event)
	}
	if cursorValue, found := jsonPathValue(document, runtime.source.CursorPath); found {
		page.nextCursor, err = canonicalCursor(cursorValue)
		if err != nil {
			return apiPage{}, err
		}
	}
	if hasMoreValue, found := jsonPathValue(document, runtime.source.HasMorePath); found {
		page.hasMore, ok = hasMoreValue.(bool)
		if !ok {
			return apiPage{}, errors.New("API has_more_path must resolve to a boolean")
		}
	}
	return page, nil
}

func normalizeAPISource(source APISource) (APISource, error) {
	source.SourceID = strings.TrimSpace(source.SourceID)
	source.URL = strings.TrimSpace(source.URL)
	source.Format = strings.TrimSpace(source.Format)
	if source.SourceID == "" || len(source.SourceID) > 128 || strings.ContainsAny(source.SourceID, "\r\n") {
		return APISource{}, errors.New("canonical source_id is required")
	}
	endpoint, err := url.Parse(source.URL)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil || endpoint.Fragment != "" || len(source.URL) > 2048 {
		return APISource{}, errors.New("url must be an absolute HTTPS URL without userinfo or fragment")
	}
	if source.Format == "" {
		source.Format = "json"
	}
	if !validCollectorFormat(source.Format) {
		return APISource{}, errors.New("invalid event format")
	}
	defaults := map[*string]string{
		&source.EventsPath: "events", &source.EventIDPath: "id", &source.CursorPath: "next_cursor", &source.HasMorePath: "has_more",
		&source.CursorQueryParameter: "cursor", &source.PageSizeQueryParameter: "limit",
	}
	for field, fallback := range defaults {
		*field = strings.TrimSpace(*field)
		if *field == "" {
			*field = fallback
		}
	}
	for _, value := range []string{source.EventsPath, source.EventIDPath, source.CursorPath, source.HasMorePath} {
		if !validJSONPath(value) {
			return APISource{}, fmt.Errorf("invalid JSON path %q", value)
		}
	}
	for _, value := range []string{source.CursorQueryParameter, source.PageSizeQueryParameter} {
		if !validName(value) {
			return APISource{}, fmt.Errorf("invalid query parameter %q", value)
		}
	}
	if source.CursorQueryParameter == source.PageSizeQueryParameter {
		return APISource{}, errors.New("cursor and page size query parameters must differ")
	}
	if source.PageSize <= 0 {
		source.PageSize = 500
	}
	if source.PageSize > 5000 || source.IntervalSeconds < 0 || source.IntervalSeconds > 86400 {
		return APISource{}, errors.New("page_size or interval_seconds is outside the allowed range")
	}
	source.AuthType = strings.ToUpper(strings.TrimSpace(source.AuthType))
	source.SecretEnv = strings.TrimSpace(source.SecretEnv)
	if source.AuthType == "" {
		if source.SecretEnv != "" {
			source.AuthType = "BEARER"
		} else {
			source.AuthType = "MTLS"
		}
	}
	if source.AuthType != "BEARER" && source.AuthType != "API_KEY" && source.AuthType != "MTLS" {
		return APISource{}, errors.New("auth_type must be BEARER, API_KEY, or MTLS")
	}
	if source.AuthType == "BEARER" || source.AuthType == "API_KEY" {
		if !validEnvironmentName(source.SecretEnv) {
			return APISource{}, errors.New("secret_env must reference an environment variable")
		}
	}
	if source.AuthType == "API_KEY" {
		source.APIKeyHeader = http.CanonicalHeaderKey(strings.TrimSpace(source.APIKeyHeader))
		if source.APIKeyHeader == "" {
			source.APIKeyHeader = "X-Api-Key"
		}
		if !validHeaderName(source.APIKeyHeader) || strings.EqualFold(source.APIKeyHeader, "Host") || strings.EqualFold(source.APIKeyHeader, "Content-Length") {
			return APISource{}, errors.New("invalid api_key_header")
		}
	}
	source.CAFile = strings.TrimSpace(source.CAFile)
	source.CertificateFile = strings.TrimSpace(source.CertificateFile)
	source.PrivateKeyFile = strings.TrimSpace(source.PrivateKeyFile)
	if (source.CertificateFile == "") != (source.PrivateKeyFile == "") {
		return APISource{}, errors.New("mTLS certificate and private key must be configured together")
	}
	if source.AuthType == "MTLS" && source.CertificateFile == "" {
		return APISource{}, errors.New("MTLS authentication requires a certificate and private key")
	}
	return source, nil
}

func apiHTTPClient(source APISource, timeout time.Duration) (*http.Client, string, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if source.CAFile != "" {
		// #nosec G304 -- CA path is trusted local collector configuration.
		body, err := os.ReadFile(source.CAFile)
		if err != nil {
			return nil, "", fmt.Errorf("read API CA: %w", err)
		}
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(body) {
			return nil, "", errors.New("API CA file contains no certificates")
		}
		tlsConfig.RootCAs = roots
	}
	if source.CertificateFile != "" {
		certificate, err := tls.LoadX509KeyPair(source.CertificateFile, source.PrivateKeyFile)
		if err != nil {
			return nil, "", fmt.Errorf("load API client identity: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{certificate}
	}
	secret := ""
	if source.SecretEnv != "" {
		secret = strings.TrimSpace(os.Getenv(source.SecretEnv))
		if secret == "" || strings.ContainsAny(secret, "\r\n") {
			return nil, "", fmt.Errorf("secret environment variable %s is empty or invalid", source.SecretEnv)
		}
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig
	client := &http.Client{
		Transport: transport, Timeout: timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return errors.New("API redirects are disabled") },
	}
	return client, secret, nil
}

func (p *APIPoller) sourceInterval(source APISource) time.Duration {
	if source.IntervalSeconds > 0 {
		return time.Duration(source.IntervalSeconds) * time.Second
	}
	return p.config.PollInterval
}

func (p *APIPoller) retryDelay(failures int, err error) time.Duration {
	delay := p.config.PollInterval
	for attempt := 1; attempt < failures && delay < p.config.MaximumBackoff/2; attempt++ {
		delay *= 2
	}
	if delay > p.config.MaximumBackoff {
		delay = p.config.MaximumBackoff
	}
	var responseErr *apiResponseError
	if errors.As(err, &responseErr) && responseErr.retryAfter > delay {
		delay = min(responseErr.retryAfter, p.config.MaximumBackoff)
	}
	return delay
}

func stableAPIEventID(source APISource, event map[string]interface{}, cursor string, index int, payload []byte) string {
	identity := ""
	if value, found := jsonPathValue(event, source.EventIDPath); found {
		identity, _ = canonicalCursor(value)
	}
	if identity == "" {
		identity = cursor + "\x00" + strconv.Itoa(index) + "\x00" + string(payload)
	}
	digest := sha256.Sum256([]byte(source.SourceID + "\x00" + identity))
	return "api_" + hex.EncodeToString(digest[:16])
}

func jsonPathValue(document interface{}, path string) (interface{}, bool) {
	if path == "$" {
		return document, true
	}
	current := document
	for _, segment := range strings.Split(path, ".") {
		object, ok := current.(map[string]interface{})
		if !ok {
			return nil, false
		}
		current, ok = object[segment]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

func canonicalCursor(value interface{}) (string, error) {
	var cursor string
	switch typed := value.(type) {
	case string:
		cursor = typed
	case json.Number:
		cursor = typed.String()
	case nil:
		return "", nil
	default:
		return "", errors.New("API cursor must be a string or number")
	}
	cursor = strings.TrimSpace(cursor)
	if len(cursor) > 2048 || strings.ContainsAny(cursor, "\r\n") {
		return "", errors.New("API cursor is invalid")
	}
	return cursor, nil
}

func validJSONPath(value string) bool {
	if value == "$" {
		return true
	}
	if value == "" || len(value) > 128 {
		return false
	}
	for _, segment := range strings.Split(value, ".") {
		if !validName(segment) {
			return false
		}
	}
	return true
}

func validName(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func validEnvironmentName(value string) bool {
	if value == "" || len(value) > 128 || value[0] >= '0' && value[0] <= '9' {
		return false
	}
	for _, character := range value {
		if character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '_' {
			continue
		}
		return false
	}
	return true
}

func validHeaderName(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func sanitizedAPIAddress(rawURL string) string {
	endpoint, _ := url.Parse(rawURL)
	return endpoint.Scheme + "://" + endpoint.Host + endpoint.EscapedPath()
}

func apiCheckpointPath(directory string, source APISource) string {
	digest := sha256.Sum256([]byte(source.SourceID + "\x00" + source.URL))
	return filepath.Join(directory, hex.EncodeToString(digest[:16])+".json")
}

func loadAPICheckpoint(directory string, source APISource) (apiCheckpoint, bool, error) {
	body, err := os.ReadFile(apiCheckpointPath(directory, source))
	if errors.Is(err, os.ErrNotExist) {
		return apiCheckpoint{}, false, nil
	}
	if err != nil {
		return apiCheckpoint{}, false, fmt.Errorf("read API checkpoint: %w", err)
	}
	var checkpoint apiCheckpoint
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&checkpoint); err != nil || checkpoint.SourceID != source.SourceID || checkpoint.URL != source.URL || len(checkpoint.Cursor) > 2048 {
		return apiCheckpoint{}, false, fmt.Errorf("invalid checkpoint for API source %q", source.SourceID)
	}
	return checkpoint, true, nil
}

func commitAPICheckpoint(directory string, source APISource, cursor string) error {
	body, err := json.Marshal(apiCheckpoint{SourceID: source.SourceID, URL: source.URL, Cursor: cursor, UpdatedAt: time.Now().UTC()})
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".checkpoint-*")
	if err != nil {
		return fmt.Errorf("create API checkpoint: %w", err)
	}
	temporaryName := temporary.Name()
	defer func() { _ = os.Remove(temporaryName) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(body); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryName, apiCheckpointPath(directory, source)); err != nil {
		return fmt.Errorf("commit API checkpoint: %w", err)
	}
	return nil
}

func parseRetryAfter(value string) time.Duration {
	value = strings.TrimSpace(value)
	if seconds, err := strconv.Atoi(value); err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	if deadline, err := http.ParseTime(value); err == nil {
		return max(time.Until(deadline), 0)
	}
	return 0
}
