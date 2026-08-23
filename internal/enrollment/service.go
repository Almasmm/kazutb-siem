package enrollment

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/platform/tenant"
	"github.com/kcsp/platform/internal/store"
)

var (
	ErrInvalidRequest = errors.New("invalid agent enrollment request")
	ErrInvalidToken   = errors.New("invalid or expired agent credential")
)

var agentIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$`)

type Config struct {
	CredentialTTL        time.Duration
	MaximumEnrollmentTTL time.Duration
	Now                  func() time.Time
}

type CreateTokenRequest struct {
	Label            string   `json:"label"`
	CollectorType    string   `json:"collector_type"`
	Capabilities     []string `json:"capabilities"`
	ExpiresInSeconds int64    `json:"expires_in_seconds"`
	MaxUses          int      `json:"max_uses"`
}

type Service struct {
	store         store.AgentEnrollmentStore
	credentialTTL time.Duration
	maximumTTL    time.Duration
	now           func() time.Time
}

func NewService(repository store.AgentEnrollmentStore, config Config) *Service {
	if config.CredentialTTL <= 0 {
		config.CredentialTTL = 30 * 24 * time.Hour
	}
	if config.MaximumEnrollmentTTL <= 0 {
		config.MaximumEnrollmentTTL = 7 * 24 * time.Hour
	}
	if config.Now == nil {
		config.Now = func() time.Time { return time.Now().UTC() }
	}
	return &Service{store: repository, credentialTTL: config.CredentialTTL, maximumTTL: config.MaximumEnrollmentTTL, now: config.Now}
}

func (s *Service) CreateToken(ctx context.Context, tenantID, actor string, request CreateTokenRequest) (core.AgentEnrollmentTokenIssue, error) {
	tenantID = strings.TrimSpace(tenantID)
	actor = strings.TrimSpace(actor)
	request.Label = strings.TrimSpace(request.Label)
	request.CollectorType = strings.ToLower(strings.TrimSpace(request.CollectorType))
	if request.CollectorType == "" {
		request.CollectorType = "lightweight-agent"
	}
	capabilities := normalizeCapabilities(request.Capabilities)
	if !tenant.Valid(tenantID) || actor == "" || request.Label == "" || len(request.Label) > 256 || len(request.CollectorType) > 64 || len(capabilities) == 0 {
		return core.AgentEnrollmentTokenIssue{}, fmt.Errorf("%w: tenant, actor, label, collector type and capabilities are required", ErrInvalidRequest)
	}
	if request.MaxUses == 0 {
		request.MaxUses = 1
	}
	if request.MaxUses < 1 || request.MaxUses > 10000 {
		return core.AgentEnrollmentTokenIssue{}, fmt.Errorf("%w: max_uses must be between 1 and 10000", ErrInvalidRequest)
	}
	if request.ExpiresInSeconds < 0 || request.ExpiresInSeconds > int64(s.maximumTTL/time.Second) {
		return core.AgentEnrollmentTokenIssue{}, fmt.Errorf("%w: enrollment token lifetime exceeds %s", ErrInvalidRequest, s.maximumTTL)
	}
	ttl := time.Duration(request.ExpiresInSeconds) * time.Second
	if ttl == 0 {
		ttl = 24 * time.Hour
	}
	if ttl > s.maximumTTL {
		return core.AgentEnrollmentTokenIssue{}, fmt.Errorf("%w: enrollment token lifetime exceeds %s", ErrInvalidRequest, s.maximumTTL)
	}
	now := s.now().UTC()
	item := core.AgentEnrollmentToken{
		ID: core.NewID("enr"), TenantID: tenantID, Label: request.Label, CollectorType: request.CollectorType,
		Capabilities: capabilities, State: core.AgentEnrollmentStateActive, ExpiresAt: now.Add(ttl),
		MaxUses: request.MaxUses, CreatedBy: actor, CreatedAt: now,
	}
	rawToken, tokenHash, err := generateSecret("kcsp_enroll", item.ID)
	if err != nil {
		return core.AgentEnrollmentTokenIssue{}, err
	}
	created, err := s.store.CreateAgentEnrollmentToken(ctx, item, tokenHash)
	if err != nil {
		return core.AgentEnrollmentTokenIssue{}, err
	}
	return core.AgentEnrollmentTokenIssue{EnrollmentToken: rawToken, Token: created}, nil
}

func (s *Service) ListTokens(ctx context.Context, tenantID string) ([]core.AgentEnrollmentToken, error) {
	return s.store.ListAgentEnrollmentTokens(ctx, strings.TrimSpace(tenantID))
}

func (s *Service) RevokeToken(ctx context.Context, tenantID, tokenID, actor string) (core.AgentEnrollmentToken, error) {
	tenantID = strings.TrimSpace(tenantID)
	tokenID = strings.TrimSpace(tokenID)
	actor = strings.TrimSpace(actor)
	if !tenant.Valid(tenantID) || tokenID == "" || actor == "" {
		return core.AgentEnrollmentToken{}, fmt.Errorf("%w: tenant, token and actor are required", ErrInvalidRequest)
	}
	return s.store.RevokeAgentEnrollmentToken(ctx, tenantID, tokenID, actor)
}

func (s *Service) Enroll(ctx context.Context, request core.AgentEnrollmentRequest, observedIP string) (core.AgentEnrollmentResponse, error) {
	request.EnrollmentToken = strings.TrimSpace(request.EnrollmentToken)
	request.AgentID = strings.TrimSpace(request.AgentID)
	request.Name = strings.TrimSpace(request.Name)
	request.Hostname = strings.TrimSpace(request.Hostname)
	request.Version = strings.TrimSpace(request.Version)
	request.Platform = strings.ToLower(strings.TrimSpace(request.Platform))
	request.Architecture = strings.ToLower(strings.TrimSpace(request.Architecture))
	if !strings.HasPrefix(request.EnrollmentToken, "kcsp_enroll_") || len(request.EnrollmentToken) > 512 {
		return core.AgentEnrollmentResponse{}, ErrInvalidToken
	}
	if !agentIDPattern.MatchString(request.AgentID) || request.Name == "" || len(request.Name) > 256 || len(request.Hostname) > 256 || len(request.Version) > 128 || len(request.Platform) > 64 || len(request.Architecture) > 64 || len(observedIP) > 128 {
		return core.AgentEnrollmentResponse{}, fmt.Errorf("%w: valid agent identity, name and bounded host metadata are required", ErrInvalidRequest)
	}
	credentialID := core.NewID("cred")
	rawCredential, credentialHash, err := generateSecret("kcsp_agent", credentialID)
	if err != nil {
		return core.AgentEnrollmentResponse{}, err
	}
	tokenHash := sha256.Sum256([]byte(request.EnrollmentToken))
	now := s.now().UTC()
	credential := core.AgentCredential{ID: credentialID, ExpiresAt: now.Add(s.credentialTTL), CreatedAt: now}
	metadata := map[string]interface{}{
		"hostname": request.Hostname, "platform": request.Platform, "architecture": request.Architecture,
		"enrollment": "one-time-token",
	}
	collector, err := s.store.ConsumeAgentEnrollment(ctx, tokenHash[:], core.Collector{
		ID: request.AgentID, Name: request.Name, AuthSubject: "agent:" + request.AgentID,
		Version: request.Version, ObservedIP: strings.TrimSpace(observedIP), HealthMetadata: metadata,
	}, credential, credentialHash)
	if errors.Is(err, store.ErrEnrollmentRejected) || errors.Is(err, store.ErrNotFound) {
		return core.AgentEnrollmentResponse{}, ErrInvalidToken
	}
	if err != nil {
		return core.AgentEnrollmentResponse{}, err
	}
	return core.AgentEnrollmentResponse{
		Collector:  collector,
		Credential: core.AgentCredentialGrant{AccessToken: rawCredential, TokenType: "Bearer", ExpiresAt: credential.ExpiresAt},
	}, nil
}

func (s *Service) RotateCredential(ctx context.Context, currentToken string) (core.AgentCredentialGrant, error) {
	currentToken = strings.TrimSpace(currentToken)
	if !strings.HasPrefix(currentToken, "kcsp_agent_") || len(currentToken) > 512 {
		return core.AgentCredentialGrant{}, ErrInvalidToken
	}
	credentialID := core.NewID("cred")
	rawCredential, replacementHash, err := generateSecret("kcsp_agent", credentialID)
	if err != nil {
		return core.AgentCredentialGrant{}, err
	}
	currentHash := sha256.Sum256([]byte(currentToken))
	replacement := core.AgentCredential{ID: credentialID, ExpiresAt: s.now().UTC().Add(s.credentialTTL)}
	created, err := s.store.RotateAgentCredential(ctx, currentHash[:], replacement, replacementHash)
	if errors.Is(err, store.ErrNotFound) {
		return core.AgentCredentialGrant{}, ErrInvalidToken
	}
	if err != nil {
		return core.AgentCredentialGrant{}, err
	}
	return core.AgentCredentialGrant{AccessToken: rawCredential, TokenType: "Bearer", ExpiresAt: created.ExpiresAt}, nil
}

func generateSecret(prefix, id string) (string, []byte, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", nil, fmt.Errorf("generate agent secret: %w", err)
	}
	raw := prefix + "_" + id + "." + base64.RawURLEncoding.EncodeToString(secret)
	hash := sha256.Sum256([]byte(raw))
	return raw, hash[:], nil
}

func normalizeCapabilities(values []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" || len(value) > 64 || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	return result
}
