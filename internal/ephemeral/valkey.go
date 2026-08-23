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
