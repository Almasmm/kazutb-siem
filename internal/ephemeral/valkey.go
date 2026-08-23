package ephemeral

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/kcsp/platform/internal/platform/quota"
	"github.com/redis/go-redis/v9"
)

var namespacePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:_-]{0,63}$`)
var scopePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:_-]{0,63}$`)

type ValkeyConfig struct {
	URL                    string
	Password               string
	Namespace              string
	RequireTLS             bool
	RequireAuthentication  bool
	DialTimeout            time.Duration
	ReadTimeout            time.Duration
	WriteTimeout           time.Duration
	OperationTimeout       time.Duration
	PoolSize               int
	MinimumIdleConnections int
}

type Valkey struct {
	client           *redis.Client
	namespace        string
	operationTimeout time.Duration
}

type FixedWindowConfig struct {
	Scope  string
	Limit  int
	Window time.Duration
}

type FixedWindowLimiter struct {
	valkey *Valkey
	scope  string
	limit  int64
	window time.Duration
}

type IngestQuotaLedger struct {
	valkey *Valkey
}

var fixedWindowScript = redis.NewScript(`
local current = redis.call('INCR', KEYS[1])
if current == 1 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
local ttl = redis.call('PTTL', KEYS[1])
if ttl < 0 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
  ttl = tonumber(ARGV[1])
end
return {current, ttl}
`)

var ingestQuotaScript = redis.NewScript(`
local events_missing = redis.call('PTTL', KEYS[1]) == -2
local bytes_missing = redis.call('PTTL', KEYS[2]) == -2
if (events_missing or bytes_missing) and ARGV[1] ~= '1' then
  return {0, 'bootstrap', 0, 0}
end

if events_missing then
  redis.call('INCRBY', KEYS[1], ARGV[2])
  redis.call('PEXPIRE', KEYS[1], ARGV[9])
end
if bytes_missing then
  redis.call('INCRBY', KEYS[2], ARGV[3])
  redis.call('PEXPIRE', KEYS[2], ARGV[9])
end

local current_events = tonumber(redis.call('INCRBY', KEYS[1], 0))
local current_bytes = tonumber(redis.call('INCRBY', KEYS[2], 0))
local current_eps = tonumber(redis.call('INCRBY', KEYS[3], 0))
if redis.call('PTTL', KEYS[3]) < 0 then
  redis.call('PEXPIRE', KEYS[3], ARGV[10])
end
local next_events = current_events + tonumber(ARGV[4])
local next_bytes = current_bytes + tonumber(ARGV[5])
local next_eps = current_eps + tonumber(ARGV[4])
local events_limit = tonumber(ARGV[6])
local bytes_limit = tonumber(ARGV[7])
local eps_limit = tonumber(ARGV[8])

if events_limit > 0 and next_events > events_limit then
  return {0, 'events_per_day', current_events, current_bytes}
end
if bytes_limit > 0 and next_bytes > bytes_limit then
  return {0, 'gb_per_day', current_events, current_bytes}
end
if eps_limit > 0 and next_eps > eps_limit then
  return {0, 'eps', current_events, current_bytes}
end

redis.call('INCRBY', KEYS[1], ARGV[4])
redis.call('INCRBY', KEYS[2], ARGV[5])
redis.call('PEXPIRE', KEYS[1], ARGV[9])
redis.call('PEXPIRE', KEYS[2], ARGV[9])
redis.call('INCRBY', KEYS[3], ARGV[4])
return {1, '', next_events, next_bytes}
`)

func OpenValkey(ctx context.Context, config ValkeyConfig) (*Valkey, error) {
	operationTimeout := config.OperationTimeout
	if operationTimeout <= 0 {
		operationTimeout = 1500 * time.Millisecond
	}
	options, namespace, err := valkeyOptions(config)
	if err != nil {
		return nil, err
	}
	client := redis.NewClient(options)
	operationContext, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	if err := client.Ping(operationContext).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("connect to Valkey: %w", err)
	}
	return &Valkey{client: client, namespace: namespace, operationTimeout: operationTimeout}, nil
}

func valkeyOptions(config ValkeyConfig) (*redis.Options, string, error) {
	rawURL := strings.TrimSpace(config.URL)
	if rawURL == "" {
		return nil, "", errors.New("Valkey URL is required")
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "redis" && parsed.Scheme != "rediss") {
		return nil, "", errors.New("Valkey URL must use redis:// or rediss:// with a host")
	}
	if config.RequireTLS && parsed.Scheme != "rediss" {
		return nil, "", errors.New("Valkey TLS is required outside development and test profiles")
	}
	options, err := redis.ParseURL(rawURL)
	if err != nil {
		return nil, "", fmt.Errorf("parse Valkey URL: %w", err)
	}
	if password := strings.TrimSpace(config.Password); password != "" {
		options.Password = password
	}
	if config.RequireAuthentication && options.Password == "" {
		return nil, "", errors.New("authenticated Valkey configuration is required outside development and test profiles")
	}
	if config.DialTimeout <= 0 {
		config.DialTimeout = 3 * time.Second
	}
	if config.ReadTimeout <= 0 {
		config.ReadTimeout = 2 * time.Second
	}
	if config.WriteTimeout <= 0 {
		config.WriteTimeout = time.Second
	}
	if config.OperationTimeout <= 0 {
		config.OperationTimeout = 1500 * time.Millisecond
	}
	if config.PoolSize <= 0 {
		config.PoolSize = 16
	}
	if config.MinimumIdleConnections < 0 {
		return nil, "", errors.New("Valkey minimum idle connections cannot be negative")
	}
	if config.DialTimeout > config.OperationTimeout {
		config.DialTimeout = config.OperationTimeout
	}
	options.DialTimeout = config.DialTimeout
	options.ReadTimeout = config.ReadTimeout
	options.WriteTimeout = config.WriteTimeout
	options.PoolSize = config.PoolSize
	options.MinIdleConns = config.MinimumIdleConnections
	options.PoolTimeout = config.OperationTimeout
	options.MaxRetries = -1
	options.DialerRetries = 1
	options.ContextTimeoutEnabled = true
	namespace := strings.TrimSpace(config.Namespace)
	if namespace == "" {
		namespace = "kcsp"
	}
	if !namespacePattern.MatchString(namespace) {
		return nil, "", errors.New("Valkey namespace contains unsupported characters or is too long")
	}
	return options, namespace, nil
}

func (v *Valkey) Close() error {
	if v == nil || v.client == nil {
		return nil
	}
	return v.client.Close()
}

func (v *Valkey) Health(ctx context.Context) error {
	if v == nil || v.client == nil {
		return errors.New("Valkey client is not configured")
	}
	operationContext, cancel := context.WithTimeout(ctx, v.operationTimeout)
	defer cancel()
	if err := v.client.Ping(operationContext).Err(); err != nil {
		return fmt.Errorf("Valkey health check: %w", err)
	}
	return nil
}

func NewFixedWindowLimiter(valkey *Valkey, config FixedWindowConfig) (*FixedWindowLimiter, error) {
	if valkey == nil || valkey.client == nil {
		return nil, errors.New("Valkey client is required for a distributed rate limiter")
	}
	config.Scope = strings.TrimSpace(config.Scope)
	if !scopePattern.MatchString(config.Scope) {
		return nil, errors.New("rate limiter scope contains unsupported characters or is too long")
	}
	if config.Limit < 1 || config.Limit > 1000000 {
		return nil, errors.New("rate limiter limit must be between 1 and 1000000")
	}
	if config.Window < time.Second || config.Window > 24*time.Hour {
		return nil, errors.New("rate limiter window must be between one second and 24 hours")
	}
	return &FixedWindowLimiter{valkey: valkey, scope: config.Scope, limit: int64(config.Limit), window: config.Window}, nil
}

func NewIngestQuotaLedger(valkey *Valkey) (*IngestQuotaLedger, error) {
	if valkey == nil || valkey.client == nil {
		return nil, errors.New("Valkey client is required for distributed ingest quotas")
	}
	return &IngestQuotaLedger{valkey: valkey}, nil
}

func (l *IngestQuotaLedger) ReserveIngest(ctx context.Context, request quota.IngestReservation) (quota.IngestResult, error) {
	if l == nil || l.valkey == nil || l.valkey.client == nil {
		return quota.IngestResult{}, errors.New("Valkey ingest quota ledger is not configured")
	}
	request.TenantID = strings.TrimSpace(request.TenantID)
	if request.TenantID == "" || request.Events < 1 || request.Bytes < 0 || request.Limits.EventsPerDay < 0 || request.Limits.BytesPerDay < 0 || request.Limits.EventsPerSec < 0 {
		return quota.IngestResult{}, errors.New("invalid ingest quota reservation")
	}
	if request.Baseline != nil && (request.Baseline.Events < 0 || request.Baseline.Bytes < 0) {
		return quota.IngestResult{}, errors.New("invalid ingest quota baseline")
	}
	now := request.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	dayStart := now.Truncate(24 * time.Hour)
	dayTTL := dayStart.Add(25 * time.Hour).Sub(now)
	if dayTTL < time.Minute {
		dayTTL = time.Minute
	}
	eventsKey, bytesKey, epsKey := l.ingestStorageKeys(request.TenantID, dayStart, now)
	baselineProvided := int64(0)
	baselineEvents := int64(0)
	baselineBytes := int64(0)
	if request.Baseline != nil {
		baselineProvided = 1
		baselineEvents = request.Baseline.Events
		baselineBytes = request.Baseline.Bytes
	}
	operationContext, cancel := context.WithTimeout(ctx, l.valkey.operationTimeout)
	defer cancel()
	values, err := ingestQuotaScript.Run(operationContext, l.valkey.client, []string{eventsKey, bytesKey, epsKey},
		baselineProvided, baselineEvents, baselineBytes, request.Events, request.Bytes,
		request.Limits.EventsPerDay, request.Limits.BytesPerDay, request.Limits.EventsPerSec,
		dayTTL.Milliseconds(), (3 * time.Second).Milliseconds()).Slice()
	if err != nil {
		return quota.IngestResult{}, fmt.Errorf("reserve distributed ingest quota: %w", err)
	}
	if len(values) != 4 {
		return quota.IngestResult{}, errors.New("reserve distributed ingest quota: unexpected Valkey response")
	}
	status, statusOK := values[0].(int64)
	limit, limitOK := values[1].(string)
	events, eventsOK := values[2].(int64)
	bytes, bytesOK := values[3].(int64)
	if !statusOK || !limitOK || !eventsOK || !bytesOK {
		return quota.IngestResult{}, errors.New("reserve distributed ingest quota: invalid Valkey response")
	}
	return quota.IngestResult{
		Allowed: status == 1, NeedsBootstrap: limit == "bootstrap", Limit: limit, Events: events, Bytes: bytes,
	}, nil
}

func (l *IngestQuotaLedger) ingestStorageKeys(tenantID string, dayStart, now time.Time) (string, string, string) {
	digest := sha256.Sum256([]byte(strings.TrimSpace(tenantID)))
	tenantKey := hex.EncodeToString(digest[:])
	prefix := l.valkey.namespace + ":quota:ingest:" + tenantKey
	day := dayStart.Format("20060102")
	return prefix + ":events:" + day, prefix + ":bytes:" + day, prefix + ":second:" + fmt.Sprintf("%d", now.Unix())
}

func (l *FixedWindowLimiter) Allow(ctx context.Context, key string) (bool, time.Duration, error) {
	storageKey := l.storageKey(key)
	operationContext, cancel := context.WithTimeout(ctx, l.valkey.operationTimeout)
	defer cancel()
	result, err := fixedWindowScript.Run(operationContext, l.valkey.client, []string{storageKey}, l.window.Milliseconds()).Slice()
	if err != nil {
		return false, 0, fmt.Errorf("apply distributed rate limit: %w", err)
	}
	if len(result) != 2 {
		return false, 0, errors.New("apply distributed rate limit: unexpected Valkey response")
	}
	count, ok := result[0].(int64)
	if !ok {
		return false, 0, errors.New("apply distributed rate limit: invalid counter response")
	}
	ttlMilliseconds, ok := result[1].(int64)
	if !ok || ttlMilliseconds < 1 {
		return false, 0, errors.New("apply distributed rate limit: invalid expiry response")
	}
	if count <= l.limit {
		return true, 0, nil
	}
	return false, time.Duration(ttlMilliseconds) * time.Millisecond, nil
}

func (l *FixedWindowLimiter) storageKey(key string) string {
	key = strings.TrimSpace(key)
	if key == "" {
		key = "unknown"
	}
	digest := sha256.Sum256([]byte(key))
	return l.valkey.namespace + ":rate:" + l.scope + ":" + hex.EncodeToString(digest[:])
}

func (l *FixedWindowLimiter) Health(ctx context.Context) error {
	return l.valkey.Health(ctx)
}
