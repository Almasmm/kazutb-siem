package threatintel

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/kcsp/platform/internal/core"
)

const (
	feedPageSize       = 500
	maximumFeedPages   = 20
	maximumFeedBody    = 16 << 20
	maximumFeedRecords = feedPageSize * maximumFeedPages
)

type FeedSyncStore interface {
	QueueThreatIntelFeedSync(context.Context, string, string, time.Time) (core.ThreatIntelFeed, error)
	ClaimThreatIntelFeedSync(context.Context, string, string, time.Time, time.Time) (core.ThreatIntelFeed, bool, error)
	FinishThreatIntelFeedSync(context.Context, string, string, string, core.ThreatIntelFeedSyncResult, time.Time) (core.ThreatIntelFeed, error)
	RecordThreatIntelFeedTest(context.Context, string, string, core.ThreatIntelFeedTestResult, time.Time) (core.ThreatIntelFeed, error)
}

type FeedSecretResolver interface {
	Resolve(context.Context, string) (string, error)
}

type FeedSecretError struct {
	Class  string
	Detail string
}

func (e *FeedSecretError) Error() string { return e.Detail }

type EnvironmentFeedSecretResolver struct{}

func (EnvironmentFeedSecretResolver) Resolve(_ context.Context, reference string) (string, error) {
	if reference == "" {
		return "", &FeedSecretError{Class: "CREDENTIALS_REQUIRED", Detail: "feed has no secret binding"}
	}
	if !feedAuthReferencePattern.MatchString(reference) {
		return "", &FeedSecretError{Class: "SECRET_REF_INVALID", Detail: "feed secret binding is invalid"}
	}
	if !strings.HasPrefix(reference, "env://") {
		return "", &FeedSecretError{Class: "SECRET_PROVIDER_UNAVAILABLE", Detail: "configured secret provider is unavailable in this deployment"}
	}
	name := strings.Trim(strings.TrimPrefix(reference, "env://"), "/")
	secret, ok := os.LookupEnv(name)
	if !ok || secret == "" {
		return "", &FeedSecretError{Class: "CREDENTIALS_REQUIRED", Detail: "bound feed credential is unavailable"}
	}
	if len(secret) > 16<<10 {
		return "", &FeedSecretError{Class: "CREDENTIALS_INVALID", Detail: "bound feed credential exceeds safe bounds"}
	}
	return secret, nil
}

type FeedRuntime struct {
	service *Service
	secrets FeedSecretResolver
	client  *http.Client
	now     func() time.Time
}

func NewFeedRuntime(service *Service, secrets FeedSecretResolver, client *http.Client) *FeedRuntime {
	if secrets == nil {
		secrets = EnvironmentFeedSecretResolver{}
	}
	return &FeedRuntime{service: service, secrets: secrets, client: client, now: func() time.Time { return time.Now().UTC() }}
}

func (r *FeedRuntime) Sync(ctx context.Context, feed core.ThreatIntelFeed) core.ThreatIntelFeedSyncResult {
	started := r.now()
	result := core.ThreatIntelFeedSyncResult{Status: core.ThreatIntelFeedSyncFailed, Cursor: feed.SyncCursor}
	secret, err := r.secrets.Resolve(ctx, feed.AuthReference)
	if err != nil {
		result.Status = core.ThreatIntelFeedSyncCredentialsNeeded
		result.ErrorClass, result.Detail = classifyFeedSecretError(err)
		result.DurationMS = time.Since(started).Milliseconds()
		return result
	}
	switch feed.Kind {
	case "MISP":
		err = r.syncMISP(ctx, feed, secret, &result)
	case "OPENCTI":
		err = r.syncOpenCTI(ctx, feed, secret, &result)
	default:
		err = &feedProviderError{Class: "CONFIGURATION", Detail: "feed kind has no provider runtime"}
	}
	if err != nil {
		result.Status = core.ThreatIntelFeedSyncFailed
		result.ErrorClass, result.Detail = classifyFeedProviderError(err)
	} else {
		result.Status = core.ThreatIntelFeedSyncSucceeded
		result.ErrorClass, result.Detail = "", "feed synchronization completed"
	}
	result.DurationMS = time.Since(started).Milliseconds()
	return result
}

func (r *FeedRuntime) Test(ctx context.Context, feed core.ThreatIntelFeed) core.ThreatIntelFeedTestResult {
	started := r.now()
	result := core.ThreatIntelFeedTestResult{Status: core.ThreatIntelFeedSyncFailed}
	secret, err := r.secrets.Resolve(ctx, feed.AuthReference)
	if err != nil {
		result.Status = core.ThreatIntelFeedSyncCredentialsNeeded
		result.ErrorClass, result.Detail = classifyFeedSecretError(err)
		result.LatencyMS = time.Since(started).Milliseconds()
		return result
	}
	var status int
	switch feed.Kind {
	case "MISP":
		status, err = r.testMISP(ctx, feed, secret)
	case "OPENCTI":
		status, err = r.testOpenCTI(ctx, feed, secret)
	default:
		err = &feedProviderError{Class: "CONFIGURATION", Detail: "feed kind has no provider runtime"}
	}
	result.HTTPStatus = status
	result.LatencyMS = time.Since(started).Milliseconds()
	if err != nil {
		result.ErrorClass, result.Detail = classifyFeedProviderError(err)
		return result
	}
	result.Status = core.ThreatIntelFeedSyncSucceeded
	result.Detail = feed.Kind + " API authentication succeeded"
	return result
}

type feedProviderError struct {
	Class  string
	Detail string
}

func (e *feedProviderError) Error() string { return e.Detail }

func classifyFeedSecretError(err error) (string, string) {
	var secretError *FeedSecretError
	if errors.As(err, &secretError) {
		return secretError.Class, secretError.Detail
	}
	return "CREDENTIALS_REQUIRED", "feed credential is unavailable"
}

func classifyFeedProviderError(err error) (string, string) {
	var providerError *feedProviderError
	if errors.As(err, &providerError) {
		return providerError.Class, providerError.Detail
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "TIMEOUT", "feed provider request timed out"
	}
	return "INTERNAL", "feed synchronization failed"
}

func (r *FeedRuntime) syncMISP(ctx context.Context, feed core.ThreatIntelFeed, secret string,
	result *core.ThreatIntelFeedSyncResult) error {
	cursor := strings.TrimSpace(feed.SyncCursor)
	for page := 1; page <= maximumFeedPages; page++ {
		requestBody := map[string]interface{}{"returnFormat": "json", "page": page, "limit": feedPageSize}
		if cursor != "" {
			requestBody["timestamp"] = cursor
		}
		payload, _ := json.Marshal(requestBody)
		endpoint, err := feedProviderURL(feed.SourceURL, "/attributes/restSearch")
		if err != nil {
			return err
		}
		body, _, err := r.doFeedRequest(ctx, http.MethodPost, endpoint, payload, "Authorization", secret)
		if err != nil {
			return err
		}
		attributes, err := parseMISPAttributes(body)
		if err != nil {
			return err
		}
		if len(attributes) == 0 {
			break
		}
		for _, attribute := range attributes {
			if attribute.Deleted {
				result.Rejected++
				continue
			}
			drafts, timestamp, err := mispAttributeDrafts(feed, attribute)
			if timestamp > cursor {
				cursor = timestamp
			}
			if err != nil {
				result.Rejected++
				continue
			}
			for _, draft := range drafts {
				if err := r.upsertFeedDraft(ctx, feed, draft, result); err != nil {
					return err
				}
			}
		}
		result.Cursor = cursor
		if len(attributes) < feedPageSize || result.Imported+result.Deduplicated+result.Rejected >= maximumFeedRecords {
			break
		}
	}
	return nil
}

type mispAttribute struct {
	ID        string `json:"id"`
	UUID      string `json:"uuid"`
	EventID   string `json:"event_id"`
	Type      string `json:"type"`
	Value     string `json:"value"`
	Comment   string `json:"comment"`
	Timestamp string `json:"timestamp"`
	ToIDS     bool   `json:"to_ids"`
	Deleted   bool   `json:"deleted"`
	Tags      []struct {
		Name string `json:"name"`
	} `json:"Tag"`
}

func parseMISPAttributes(body []byte) ([]mispAttribute, error) {
	var envelope struct {
		Response struct {
			Attributes []mispAttribute `json:"Attribute"`
		} `json:"response"`
	}
	if json.Unmarshal(body, &envelope) != nil {
		return nil, &feedProviderError{Class: "PROTOCOL", Detail: "MISP returned an invalid JSON response"}
	}
	return envelope.Response.Attributes, nil
}

func mispAttributeDrafts(feed core.ThreatIntelFeed, attribute mispAttribute) ([]IndicatorDraft, string, error) {
	seen := time.Now().UTC()
	if unix, err := strconv.ParseInt(attribute.Timestamp, 10, 64); err == nil && unix > 0 {
		seen = time.Unix(unix, 0).UTC()
	}
	tags := make([]string, 0, len(attribute.Tags)+len(feed.Tags))
	tags = append(tags, feed.Tags...)
	for _, tag := range attribute.Tags {
		tags = append(tags, tag.Name)
	}
	reputation := "SUSPICIOUS"
	if attribute.ToIDS {
		reputation = "MALICIOUS"
	}
	externalID := attribute.UUID
	if externalID == "" {
		externalID = attribute.ID
	}
	base := IndicatorDraft{Source: "MISP", Reputation: reputation, FirstSeen: seen, LastSeen: seen,
		ValidFrom: seen, Tags: tags, Description: attribute.Comment, ExternalID: externalID}
	value := strings.TrimSpace(attribute.Value)
	appendDraft := func(kind core.ThreatIndicatorType, candidate string, suffix string) IndicatorDraft {
		draft := base
		draft.Type, draft.Value = kind, strings.TrimSpace(candidate)
		if suffix != "" {
			draft.ExternalID += suffix
		}
		return draft
	}
	switch strings.ToLower(strings.TrimSpace(attribute.Type)) {
	case "ip-src", "ip-dst":
		return []IndicatorDraft{appendDraft(core.ThreatIndicatorIPv4, value, "")}, attribute.Timestamp, nil
	case "ip-src|port", "ip-dst|port":
		return []IndicatorDraft{appendDraft(core.ThreatIndicatorIPv4, strings.SplitN(value, "|", 2)[0], "")}, attribute.Timestamp, nil
	case "domain", "hostname":
		return []IndicatorDraft{appendDraft(core.ThreatIndicatorDomain, value, "")}, attribute.Timestamp, nil
	case "domain|ip":
		parts := strings.SplitN(value, "|", 2)
		if len(parts) != 2 {
			return nil, attribute.Timestamp, ErrInvalidIndicator
		}
		return []IndicatorDraft{
			appendDraft(core.ThreatIndicatorDomain, parts[0], "#domain"),
			appendDraft(core.ThreatIndicatorIPv4, parts[1], "#ip"),
		}, attribute.Timestamp, nil
	case "url", "uri":
		return []IndicatorDraft{appendDraft(core.ThreatIndicatorURL, value, "")}, attribute.Timestamp, nil
	case "md5", "sha1", "sha256", "sha512":
		return []IndicatorDraft{appendDraft(core.ThreatIndicatorHash, value, "")}, attribute.Timestamp, nil
	case "filename|md5", "filename|sha1", "filename|sha256", "filename|sha512":
		parts := strings.SplitN(value, "|", 2)
		if len(parts) != 2 {
			return nil, attribute.Timestamp, ErrInvalidIndicator
		}
		return []IndicatorDraft{appendDraft(core.ThreatIndicatorHash, parts[1], "")}, attribute.Timestamp, nil
	case "email-src", "email-dst", "email-reply-to":
		return []IndicatorDraft{appendDraft(core.ThreatIndicatorEmail, value, "")}, attribute.Timestamp, nil
	case "x509-fingerprint-md5", "x509-fingerprint-sha1", "x509-fingerprint-sha256":
		return []IndicatorDraft{appendDraft(core.ThreatIndicatorCertificateFingerprint, value, "")}, attribute.Timestamp, nil
	default:
		return nil, attribute.Timestamp, ErrInvalidIndicator
	}
}

const openCTIIndicatorsQuery = `query KcspIndicators($first: Int!, $after: ID) {
  indicators(first: $first, after: $after, orderBy: updated_at, orderMode: asc) {
    edges { cursor node { id standard_id pattern pattern_type confidence revoked valid_from valid_until created_at updated_at description
      objectLabel { edges { node { value } } }
    } }
    pageInfo { hasNextPage endCursor }
  }
}`

func (r *FeedRuntime) syncOpenCTI(ctx context.Context, feed core.ThreatIntelFeed, secret string,
	result *core.ThreatIntelFeedSyncResult) error {
	cursor := strings.TrimSpace(feed.SyncCursor)
	for page := 0; page < maximumFeedPages; page++ {
		variables := map[string]interface{}{"first": feedPageSize, "after": nil}
		if cursor != "" {
			variables["after"] = cursor
		}
		payload, _ := json.Marshal(map[string]interface{}{"query": openCTIIndicatorsQuery, "variables": variables})
		endpoint, err := feedProviderURL(feed.SourceURL, "/graphql")
		if err != nil {
			return err
		}
		body, _, err := r.doFeedRequest(ctx, http.MethodPost, endpoint, payload, "Authorization", "Bearer "+secret)
		if err != nil {
			return err
		}
		pageResult, err := parseOpenCTIPage(body)
		if err != nil {
			return err
		}
		for _, edge := range pageResult.Data.Indicators.Edges {
			if edge.Node.Revoked {
				result.Rejected++
				continue
			}
			draft, err := openCTIIndicatorDraft(feed, edge.Node)
			if err != nil {
				result.Rejected++
				continue
			}
			if err := r.upsertFeedDraft(ctx, feed, draft, result); err != nil {
				return err
			}
		}
		if pageResult.Data.Indicators.PageInfo.EndCursor != "" {
			cursor = pageResult.Data.Indicators.PageInfo.EndCursor
			result.Cursor = cursor
		}
		if !pageResult.Data.Indicators.PageInfo.HasNextPage {
			break
		}
		if pageResult.Data.Indicators.PageInfo.EndCursor == "" {
			return &feedProviderError{Class: "PROTOCOL", Detail: "OpenCTI pagination omitted endCursor"}
		}
	}
	return nil
}

type openCTINode struct {
	ID          string `json:"id"`
	StandardID  string `json:"standard_id"`
	Pattern     string `json:"pattern"`
	PatternType string `json:"pattern_type"`
	Confidence  int    `json:"confidence"`
	Revoked     bool   `json:"revoked"`
	ValidFrom   string `json:"valid_from"`
	ValidUntil  string `json:"valid_until"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
	Description string `json:"description"`
	ObjectLabel struct {
		Edges []struct {
			Node struct {
				Value string `json:"value"`
			} `json:"node"`
		} `json:"edges"`
	} `json:"objectLabel"`
}

type openCTIPage struct {
	Data struct {
		Indicators struct {
			Edges []struct {
				Cursor string      `json:"cursor"`
				Node   openCTINode `json:"node"`
			} `json:"edges"`
			PageInfo struct {
				HasNextPage bool   `json:"hasNextPage"`
				EndCursor   string `json:"endCursor"`
			} `json:"pageInfo"`
		} `json:"indicators"`
	} `json:"data"`
	Errors []json.RawMessage `json:"errors"`
}

func parseOpenCTIPage(body []byte) (openCTIPage, error) {
	var result openCTIPage
	if json.Unmarshal(body, &result) != nil || len(result.Errors) > 0 {
		return result, &feedProviderError{Class: "PROTOCOL", Detail: "OpenCTI GraphQL query failed"}
	}
	return result, nil
}

func openCTIIndicatorDraft(feed core.ThreatIntelFeed, node openCTINode) (IndicatorDraft, error) {
	if node.PatternType != "" && !strings.EqualFold(node.PatternType, "stix") && !strings.EqualFold(node.PatternType, "stix2") {
		return IndicatorDraft{}, ErrInvalidIndicator
	}
	indicatorType, value, err := ParseSTIXPattern(node.Pattern)
	if err != nil {
		return IndicatorDraft{}, err
	}
	firstSeen := parseProviderTime(node.ValidFrom)
	if firstSeen.IsZero() {
		firstSeen = parseProviderTime(node.CreatedAt)
	}
	lastSeen := parseProviderTime(node.UpdatedAt)
	if lastSeen.IsZero() || lastSeen.Before(firstSeen) {
		lastSeen = firstSeen
	}
	var validUntil *time.Time
	if parsed := parseProviderTime(node.ValidUntil); !parsed.IsZero() && parsed.After(firstSeen) {
		validUntil = &parsed
	}
	confidence := node.Confidence
	if confidence < 0 || confidence > 100 {
		confidence = feed.DefaultConfidence
	}
	reputation := "UNKNOWN"
	if confidence >= 80 {
		reputation = "MALICIOUS"
	} else if confidence >= 50 {
		reputation = "SUSPICIOUS"
	}
	tags := append([]string{}, feed.Tags...)
	for _, edge := range node.ObjectLabel.Edges {
		tags = append(tags, edge.Node.Value)
	}
	externalID := node.StandardID
	if externalID == "" {
		externalID = node.ID
	}
	return IndicatorDraft{
		Type: indicatorType, Value: value, Source: "OpenCTI", Confidence: &confidence,
		Reputation: reputation, FirstSeen: firstSeen, LastSeen: lastSeen, ValidFrom: firstSeen,
		ValidUntil: validUntil, Tags: tags, Description: node.Description, ExternalID: externalID,
	}, nil
}

func (r *FeedRuntime) upsertFeedDraft(ctx context.Context, feed core.ThreatIntelFeed, draft IndicatorDraft,
	result *core.ThreatIntelFeedSyncResult) error {
	_, created, err := r.service.upsertIndicatorForFeed(ctx, feed.TenantID, "threat-intel-sync", feed, draft)
	if err != nil {
		if errors.Is(err, ErrInvalidIndicator) {
			result.Rejected++
			return nil
		}
		return &feedProviderError{Class: "STORAGE", Detail: "normalized indicator could not be persisted"}
	}
	if created {
		result.Imported++
	} else {
		result.Deduplicated++
	}
	return nil
}

func (r *FeedRuntime) testMISP(ctx context.Context, feed core.ThreatIntelFeed, secret string) (int, error) {
	endpoint, err := feedProviderURL(feed.SourceURL, "/servers/getVersion")
	if err != nil {
		return 0, err
	}
	body, status, err := r.doFeedRequest(ctx, http.MethodGet, endpoint, nil, "Authorization", secret)
	if err != nil {
		return status, err
	}
	if !json.Valid(body) {
		return status, &feedProviderError{Class: "PROTOCOL", Detail: "MISP returned an invalid health response"}
	}
	return status, nil
}

func (r *FeedRuntime) testOpenCTI(ctx context.Context, feed core.ThreatIntelFeed, secret string) (int, error) {
	endpoint, err := feedProviderURL(feed.SourceURL, "/graphql")
	if err != nil {
		return 0, err
	}
	payload, _ := json.Marshal(map[string]interface{}{"query": "query KcspHealth { about { version } }"})
	body, status, err := r.doFeedRequest(ctx, http.MethodPost, endpoint, payload, "Authorization", "Bearer "+secret)
	if err != nil {
		return status, err
	}
	var response struct {
		Data   map[string]interface{} `json:"data"`
		Errors []json.RawMessage      `json:"errors"`
	}
	if json.Unmarshal(body, &response) != nil || len(response.Errors) > 0 || response.Data == nil {
		return status, &feedProviderError{Class: "PROTOCOL", Detail: "OpenCTI returned an invalid health response"}
	}
	return status, nil
}

func feedProviderURL(raw, apiPath string) (*url.URL, error) {
	endpoint, err := url.Parse(raw)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return nil, &feedProviderError{Class: "CONFIGURATION", Detail: "feed source URL is invalid"}
	}
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + apiPath
	endpoint.RawPath = ""
	return endpoint, nil
}

func (r *FeedRuntime) doFeedRequest(ctx context.Context, method string, endpoint *url.URL, payload []byte,
	authHeader, authValue string) ([]byte, int, error) {
	client := r.client
	if client == nil {
		client = secureFeedHTTPClient(30 * time.Second)
	}
	for attempt := 1; attempt <= 3; attempt++ {
		request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), bytes.NewReader(payload))
		if err != nil {
			return nil, 0, &feedProviderError{Class: "CONFIGURATION", Detail: "feed provider request is invalid"}
		}
		request.Header.Set("Accept", "application/json")
		request.Header.Set("User-Agent", "KCSP-Threat-Intel-Feed/1.0")
		if len(payload) > 0 {
			request.Header.Set("Content-Type", "application/json")
		}
		request.Header.Set(authHeader, authValue)
		response, err := client.Do(request)
		if err != nil {
			if attempt < 3 && waitFeedRetry(ctx, attempt) {
				continue
			}
			return nil, 0, classifyFeedHTTPError(err)
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, maximumFeedBody+1))
		_ = response.Body.Close()
		if readErr != nil {
			return nil, response.StatusCode, &feedProviderError{Class: "NETWORK", Detail: "feed provider response could not be read"}
		}
		if len(body) > maximumFeedBody {
			return nil, response.StatusCode, &feedProviderError{Class: "PROTOCOL", Detail: "feed provider response exceeds 16 MiB"}
		}
		if response.StatusCode >= 200 && response.StatusCode < 300 {
			return body, response.StatusCode, nil
		}
		if attempt < 3 && (response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= 500) && waitFeedRetry(ctx, attempt) {
			continue
		}
		class := "PROTOCOL"
		switch {
		case response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden:
			class = "AUTHENTICATION"
		case response.StatusCode == http.StatusTooManyRequests:
			class = "RATE_LIMITED"
		case response.StatusCode >= 500:
			class = "UPSTREAM"
		}
		return nil, response.StatusCode, &feedProviderError{Class: class, Detail: fmt.Sprintf("feed provider returned HTTP %d", response.StatusCode)}
	}
	return nil, 0, &feedProviderError{Class: "NETWORK", Detail: "feed provider request failed"}
}

func waitFeedRetry(ctx context.Context, attempt int) bool {
	timer := time.NewTimer(time.Duration(attempt) * 200 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func classifyFeedHTTPError(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return &feedProviderError{Class: "TIMEOUT", Detail: "feed provider request timed out"}
	}
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "tls") || strings.Contains(message, "certificate") {
		return &feedProviderError{Class: "TLS", Detail: "feed provider TLS validation failed"}
	}
	if strings.Contains(message, "redirect") {
		return &feedProviderError{Class: "REDIRECT_FORBIDDEN", Detail: "feed provider attempted an HTTP redirect"}
	}
	if strings.Contains(message, "forbidden address") {
		return &feedProviderError{Class: "ENDPOINT_FORBIDDEN", Detail: "feed provider resolved to a forbidden address"}
	}
	return &feedProviderError{Class: "NETWORK", Detail: "feed provider request failed"}
}

func secureFeedHTTPClient(timeout time.Duration) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	dialer := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, errors.New("feed address is invalid")
		}
		addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, errors.New("feed host resolution failed")
		}
		for _, address := range addresses {
			ip := address.IP
			if ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
				continue
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		}
		return nil, errors.New("feed host resolves only to forbidden addresses")
	}
	return &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("feed redirects are forbidden")
	}}
}

func parseProviderTime(value string) time.Time {
	parsed, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(value))
	if err != nil {
		return time.Time{}
	}
	return parsed.UTC()
}

type FeedSyncWorkerConfig struct {
	ID           string
	TenantScope  string
	PollInterval time.Duration
	Lease        time.Duration
}

type FeedSyncWorker struct {
	store   FeedSyncStore
	runtime *FeedRuntime
	config  FeedSyncWorkerConfig
	logger  *slog.Logger
	now     func() time.Time
}

func NewFeedSyncWorker(store FeedSyncStore, runtime *FeedRuntime, config FeedSyncWorkerConfig, logger *slog.Logger) *FeedSyncWorker {
	if config.PollInterval <= 0 {
		config.PollInterval = 5 * time.Second
	}
	if config.Lease < 30*time.Second {
		config.Lease = 2 * time.Minute
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &FeedSyncWorker{store: store, runtime: runtime, config: config, logger: logger, now: func() time.Time { return time.Now().UTC() }}
}

func (w *FeedSyncWorker) Run(ctx context.Context) {
	for {
		worked, err := w.ProcessOne(ctx)
		if err != nil && !errors.Is(err, context.Canceled) {
			w.logger.Error("threat intelligence feed worker failed", "error", err)
		}
		if worked {
			continue
		}
		timer := time.NewTimer(w.config.PollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (w *FeedSyncWorker) ProcessOne(ctx context.Context) (bool, error) {
	if w.store == nil || w.runtime == nil || strings.TrimSpace(w.config.ID) == "" {
		return false, ErrFeedSyncUnavailable
	}
	now := w.now()
	feed, found, err := w.store.ClaimThreatIntelFeedSync(ctx, w.config.ID, w.config.TenantScope, now, now.Add(w.config.Lease))
	if err != nil || !found {
		return found, err
	}
	result := w.runtime.Sync(ctx, feed)
	completed := w.now()
	if _, err := w.store.FinishThreatIntelFeedSync(ctx, feed.TenantID, feed.ID, w.config.ID, result, completed); err != nil {
		return true, err
	}
	if auditStore, ok := w.store.(interface {
		AppendAudit(context.Context, core.AuditEntry) (core.AuditEntry, error)
	}); ok {
		outcome := "SUCCESS"
		if result.Status != core.ThreatIntelFeedSyncSucceeded {
			outcome = "FAILURE"
		}
		_, err = auditStore.AppendAudit(ctx, core.AuditEntry{
			ID: core.NewID("aud"), TenantID: feed.TenantID, Actor: "threat-intel-worker:" + w.config.ID,
			Action: "threat_intel.feed.sync.completed", ResourceType: "threat_intel_feed", ResourceID: feed.ID,
			Outcome: outcome, RequestID: core.NewID("sync"), CreatedAt: completed,
			Metadata: map[string]interface{}{"status": result.Status, "imported": result.Imported,
				"deduplicated": result.Deduplicated, "rejected": result.Rejected, "error_class": result.ErrorClass},
		})
		if err != nil {
			return true, err
		}
	}
	return true, nil
}
