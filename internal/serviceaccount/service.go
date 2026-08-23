package serviceaccount

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/platform/auth"
	"github.com/kcsp/platform/internal/platform/tenant"
	"github.com/kcsp/platform/internal/store"
)

var (
	ErrInvalidRequest = errors.New("invalid service account request")
	ErrScopeDenied    = errors.New("service account scope denied")
)

var serviceAccountNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._@/-]{2,127}$`)

var humanOnlyScopes = map[string]bool{
	"platform.service_accounts.write": true,
	"admin.users.manage":              true,
	"admin.roles.manage":              true,
	"admin.config.manage":             true,
	"licenses.install":                true,
	"soar.actions.approve":            true,
	"ai.decide":                       true,
}

type Config struct {
	DefaultTTL time.Duration
	MaximumTTL time.Duration
	Now        func() time.Time
}

type CreateRequest struct {
	Name             string   `json:"name"`
	Description      string   `json:"description,omitempty"`
	Scopes           []string `json:"scopes"`
	ExpiresInSeconds int64    `json:"expires_in_seconds,omitempty"`
}

type RotateRequest struct {
	ExpiresInSeconds int64 `json:"expires_in_seconds,omitempty"`
}

type Service struct {
	store      store.ServiceAccountStore
	defaultTTL time.Duration
	maximumTTL time.Duration
	now        func() time.Time
}

func NewService(repository store.ServiceAccountStore, config Config) *Service {
	if config.DefaultTTL <= 0 {
		config.DefaultTTL = 90 * 24 * time.Hour
	}
	if config.MaximumTTL < config.DefaultTTL {
		config.MaximumTTL = 365 * 24 * time.Hour
	}
	if config.Now == nil {
		config.Now = func() time.Time { return time.Now().UTC() }
	}
	return &Service{store: repository, defaultTTL: config.DefaultTTL, maximumTTL: config.MaximumTTL, now: config.Now}
}

func (s *Service) Create(ctx context.Context, tenantID string, actor auth.Principal, request CreateRequest) (core.ServiceAccountTokenIssue, error) {
	tenantID = strings.TrimSpace(tenantID)
	request.Name = strings.TrimSpace(request.Name)
	request.Description = strings.TrimSpace(request.Description)
	scopes, err := grantableScopes(actor, request.Scopes)
	if !tenant.Valid(tenantID) || !actor.CanAccessTenant(tenantID) || strings.TrimSpace(actor.ID) == "" || !serviceAccountNamePattern.MatchString(request.Name) || len(request.Description) > 1024 || err != nil {
		if err != nil {
			return core.ServiceAccountTokenIssue{}, err
		}
		return core.ServiceAccountTokenIssue{}, fmt.Errorf("%w: tenant, actor, name and scopes are required", ErrInvalidRequest)
	}
	ttl, err := s.ttl(request.ExpiresInSeconds)
	if err != nil {
		return core.ServiceAccountTokenIssue{}, err
	}
	now := s.now().UTC()
	account := core.ServiceAccount{
		ID: core.NewID("svc"), TenantID: tenantID, Name: request.Name, Description: request.Description,
		Scopes: scopes, State: core.ServiceAccountStateActive, TokenVersion: 1, CreatedBy: actor.ID,
		CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(ttl),
	}
	rawToken, tokenHash, err := generateToken(account.ID)
	if err != nil {
		return core.ServiceAccountTokenIssue{}, err
	}
	created, err := s.store.CreateServiceAccount(ctx, account, tokenHash)
	if err != nil {
		return core.ServiceAccountTokenIssue{}, err
	}
	return core.ServiceAccountTokenIssue{AccessToken: rawToken, TokenType: "Bearer", ServiceAccount: created}, nil
}

func (s *Service) List(ctx context.Context, tenantID string) ([]core.ServiceAccount, error) {
	return s.store.ListServiceAccounts(ctx, strings.TrimSpace(tenantID))
}

func (s *Service) Rotate(ctx context.Context, tenantID, accountID string, actor auth.Principal, request RotateRequest) (core.ServiceAccountTokenIssue, error) {
	tenantID = strings.TrimSpace(tenantID)
	accountID = strings.TrimSpace(accountID)
	if !tenant.Valid(tenantID) || !actor.CanAccessTenant(tenantID) || accountID == "" || actor.ID == "" {
		return core.ServiceAccountTokenIssue{}, ErrInvalidRequest
	}
	ttl, err := s.ttl(request.ExpiresInSeconds)
	if err != nil {
		return core.ServiceAccountTokenIssue{}, err
	}
	rawToken, tokenHash, err := generateToken(accountID)
	if err != nil {
		return core.ServiceAccountTokenIssue{}, err
	}
	account, err := s.store.RotateServiceAccountToken(ctx, tenantID, accountID, actor.ID, tokenHash, s.now().UTC().Add(ttl))
	if err != nil {
		return core.ServiceAccountTokenIssue{}, err
	}
	return core.ServiceAccountTokenIssue{AccessToken: rawToken, TokenType: "Bearer", ServiceAccount: account}, nil
}

func (s *Service) Revoke(ctx context.Context, tenantID, accountID string, actor auth.Principal) (core.ServiceAccount, error) {
	tenantID = strings.TrimSpace(tenantID)
	accountID = strings.TrimSpace(accountID)
	if !tenant.Valid(tenantID) || !actor.CanAccessTenant(tenantID) || accountID == "" || actor.ID == "" {
		return core.ServiceAccount{}, ErrInvalidRequest
	}
	return s.store.RevokeServiceAccount(ctx, tenantID, accountID, actor.ID)
}

func (s *Service) ttl(seconds int64) (time.Duration, error) {
	if seconds < 0 || seconds > int64(s.maximumTTL/time.Second) {
		return 0, fmt.Errorf("%w: token lifetime exceeds %s", ErrInvalidRequest, s.maximumTTL)
	}
	if seconds == 0 {
		return s.defaultTTL, nil
	}
	return time.Duration(seconds) * time.Second, nil
}

func grantableScopes(actor auth.Principal, values []string) ([]string, error) {
	if len(values) == 0 || len(values) > 32 {
		return nil, fmt.Errorf("%w: between 1 and 32 explicit scopes are required", ErrInvalidRequest)
	}
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || value == "*" || !auth.IsKnownPermission(value) {
			return nil, fmt.Errorf("%w: unknown or wildcard scope %q", ErrScopeDenied, value)
		}
		if humanOnlyScopes[value] || !actor.Can(value) {
			return nil, fmt.Errorf("%w: %s", ErrScopeDenied, value)
		}
		if !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result, nil
}

func generateToken(accountID string) (string, []byte, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", nil, fmt.Errorf("generate service account token: %w", err)
	}
	raw := "kcsp_sat_" + accountID + "." + base64.RawURLEncoding.EncodeToString(secret)
	hash := sha256.Sum256([]byte(raw))
	return raw, hash[:], nil
}
