package soar

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/kcsp/platform/internal/core"
)

var ErrInvalidConnector = errors.New("invalid SOAR connector")

type ConnectorControlStore interface {
	CreateSOARConnector(context.Context, core.SOARConnector) (core.SOARConnector, error)
	GetSOARConnector(context.Context, string, string) (core.SOARConnector, error)
	ListSOARConnectors(context.Context, string, core.SOARConnectorFilter) ([]core.SOARConnector, error)
	UpdateSOARConnector(context.Context, core.SOARConnector, int) (core.SOARConnector, error)
	DisableSOARConnector(context.Context, string, string, string, int) (core.SOARConnector, error)
	CreateSOARConnectorTest(context.Context, core.SOARConnectorTest) (core.SOARConnectorTest, bool, error)
	ListSOARConnectorTests(context.Context, string, string, int) ([]core.SOARConnectorTest, error)
}

type ConnectorDraft struct {
	Name               string                 `json:"name"`
	Kind               string                 `json:"kind"`
	Endpoint           string                 `json:"endpoint"`
	AuthType           string                 `json:"auth_type"`
	SecretRef          string                 `json:"secret_ref,omitempty"`
	AllowedActions     []string               `json:"allowed_actions"`
	Settings           map[string]interface{} `json:"settings,omitempty"`
	TimeoutSeconds     int                    `json:"timeout_seconds,omitempty"`
	Retry              core.SOARRetryPolicy   `json:"retry,omitempty"`
	RateLimitPerMinute int                    `json:"rate_limit_per_minute,omitempty"`
}

type ConnectorPatch struct {
	Version            int                    `json:"version"`
	Name               string                 `json:"name,omitempty"`
	Endpoint           string                 `json:"endpoint,omitempty"`
	AuthType           string                 `json:"auth_type,omitempty"`
	SecretRef          *string                `json:"secret_ref,omitempty"`
	AllowedActions     []string               `json:"allowed_actions,omitempty"`
	Settings           map[string]interface{} `json:"settings,omitempty"`
	TimeoutSeconds     int                    `json:"timeout_seconds,omitempty"`
	Retry              core.SOARRetryPolicy   `json:"retry,omitempty"`
	RateLimitPerMinute int                    `json:"rate_limit_per_minute,omitempty"`
}

var secretEnvironmentName = regexp.MustCompile(`^KCSP_CONNECTOR_SECRET_[A-Z0-9_]{1,96}$`)

func (s *Service) CreateConnector(ctx context.Context, tenantID, actor string,
	draft ConnectorDraft) (core.SOARConnector, error) {
	repository, err := s.connectorControlStore()
	if err != nil {
		return core.SOARConnector{}, err
	}
	connector, err := normalizeConnectorDraft(draft)
	if err != nil {
		return core.SOARConnector{}, err
	}
	now := s.now()
	connector.ID = core.NewID("scn")
	connector.TenantID = tenantID
	connector.Version = 1
	connector.CreatedBy = actor
	connector.UpdatedBy = actor
	connector.CreatedAt = now
	connector.UpdatedAt = now
	if tenantID == "" || strings.TrimSpace(actor) == "" {
		return core.SOARConnector{}, fmt.Errorf("%w: tenant and actor are required", ErrInvalidConnector)
	}
	return repository.CreateSOARConnector(ctx, connector)
}

func (s *Service) Connector(ctx context.Context, tenantID, connectorID string) (core.SOARConnector, error) {
	repository, err := s.connectorControlStore()
	if err != nil {
		return core.SOARConnector{}, err
	}
	return repository.GetSOARConnector(ctx, tenantID, strings.TrimSpace(connectorID))
}

func (s *Service) Connectors(ctx context.Context, tenantID string,
	filter core.SOARConnectorFilter) ([]core.SOARConnector, error) {
	repository, err := s.connectorControlStore()
	if err != nil {
		return nil, err
	}
	filter.Kind = strings.ToUpper(strings.TrimSpace(filter.Kind))
	filter.State = strings.ToUpper(strings.TrimSpace(filter.State))
	if filter.Kind != "" && filter.Kind != core.SOARConnectorKindWebhook {
		return nil, fmt.Errorf("%w: unsupported connector kind", ErrInvalidConnector)
	}
	switch filter.State {
	case "", core.SOARConnectorConfigured, core.SOARConnectorCredentialsNeeded, core.SOARConnectorReady,
		core.SOARConnectorDegraded, core.SOARConnectorDisabled:
	default:
		return nil, fmt.Errorf("%w: unsupported connector state", ErrInvalidConnector)
	}
	if filter.Limit <= 0 {
		filter.Limit = 100
	}
	return repository.ListSOARConnectors(ctx, tenantID, filter)
}

func (s *Service) UpdateConnector(ctx context.Context, tenantID, connectorID, actor string,
	patch ConnectorPatch) (core.SOARConnector, error) {
	repository, err := s.connectorControlStore()
	if err != nil {
		return core.SOARConnector{}, err
	}
	if patch.Version < 1 {
		return core.SOARConnector{}, fmt.Errorf("%w: connector version is required", ErrInvalidConnector)
	}
	current, err := repository.GetSOARConnector(ctx, tenantID, connectorID)
	if err != nil {
		return core.SOARConnector{}, err
	}
	if current.State == core.SOARConnectorDisabled {
		return core.SOARConnector{}, fmt.Errorf("%w: disabled connectors are immutable", ErrInvalidState)
	}
	draft := ConnectorDraft{
		Name: current.Name, Kind: current.Kind, Endpoint: current.Endpoint, AuthType: current.AuthType,
		SecretRef: current.SecretRef, AllowedActions: current.AllowedActions, Settings: current.Settings,
		TimeoutSeconds: current.TimeoutSeconds, Retry: current.Retry, RateLimitPerMinute: current.RateLimitPerMinute,
	}
	if strings.TrimSpace(patch.Name) != "" {
		draft.Name = patch.Name
	}
	if strings.TrimSpace(patch.Endpoint) != "" {
		draft.Endpoint = patch.Endpoint
	}
	if strings.TrimSpace(patch.AuthType) != "" {
		draft.AuthType = patch.AuthType
	}
	if patch.SecretRef != nil {
		draft.SecretRef = *patch.SecretRef
	}
	if patch.AllowedActions != nil {
		draft.AllowedActions = patch.AllowedActions
	}
	if patch.Settings != nil {
		draft.Settings = patch.Settings
	}
	if patch.TimeoutSeconds > 0 {
		draft.TimeoutSeconds = patch.TimeoutSeconds
	}
	if patch.Retry.MaximumAttempts > 0 {
		draft.Retry = patch.Retry
	}
	if patch.RateLimitPerMinute > 0 {
		draft.RateLimitPerMinute = patch.RateLimitPerMinute
	}
	normalized, err := normalizeConnectorDraft(draft)
	if err != nil {
		return core.SOARConnector{}, err
	}
	normalized.ID = current.ID
	normalized.TenantID = current.TenantID
	normalized.CreatedBy = current.CreatedBy
	normalized.CreatedAt = current.CreatedAt
	normalized.UpdatedBy = actor
	normalized.UpdatedAt = s.now()
	return repository.UpdateSOARConnector(ctx, normalized, patch.Version)
}

func (s *Service) DisableConnector(ctx context.Context, tenantID, connectorID, actor string,
	version int) (core.SOARConnector, error) {
	repository, err := s.connectorControlStore()
	if err != nil {
		return core.SOARConnector{}, err
	}
	if version < 1 {
		return core.SOARConnector{}, fmt.Errorf("%w: connector version is required", ErrInvalidConnector)
	}
	return repository.DisableSOARConnector(ctx, tenantID, connectorID, actor, version)
}

func (s *Service) QueueConnectorTest(ctx context.Context, tenantID, connectorID, actor,
	requestID string) (core.SOARConnectorTest, bool, error) {
	repository, err := s.connectorControlStore()
	if err != nil {
		return core.SOARConnectorTest{}, false, err
	}
	requestID = strings.TrimSpace(requestID)
	if connectorID == "" || actor == "" || len(requestID) < 8 || len(requestID) > 200 {
		return core.SOARConnectorTest{}, false, fmt.Errorf("%w: connector, actor, and an 8-200 character request_id are required", ErrInvalidConnector)
	}
	now := s.now()
	return repository.CreateSOARConnectorTest(ctx, core.SOARConnectorTest{
		ID: core.NewID("sct"), TenantID: tenantID, ConnectorID: connectorID, RequestID: requestID,
		Status: core.SOARConnectorTestQueued, TestedBy: actor, CreatedAt: now,
	})
}

func (s *Service) ConnectorTests(ctx context.Context, tenantID, connectorID string,
	limit int) ([]core.SOARConnectorTest, error) {
	repository, err := s.connectorControlStore()
	if err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 100
	}
	return repository.ListSOARConnectorTests(ctx, tenantID, connectorID, limit)
}

func normalizeConnectorDraft(draft ConnectorDraft) (core.SOARConnector, error) {
	draft.Name = strings.TrimSpace(draft.Name)
	draft.Kind = strings.ToUpper(strings.TrimSpace(draft.Kind))
	draft.Endpoint = strings.TrimSpace(draft.Endpoint)
	draft.AuthType = strings.ToUpper(strings.TrimSpace(draft.AuthType))
	draft.SecretRef = strings.TrimSpace(draft.SecretRef)
	if len(draft.Name) < 2 || len(draft.Name) > 160 || draft.Kind != core.SOARConnectorKindWebhook {
		return core.SOARConnector{}, fmt.Errorf("%w: a 2-160 character name and WEBHOOK kind are required", ErrInvalidConnector)
	}
	endpoint, err := url.Parse(draft.Endpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil ||
		endpoint.Fragment != "" || endpoint.RawQuery != "" {
		return core.SOARConnector{}, fmt.Errorf("%w: endpoint must be an absolute HTTPS URL without credentials, query, or fragment", ErrInvalidConnector)
	}
	switch draft.AuthType {
	case core.SOARConnectorAuthNone, core.SOARConnectorAuthBearer, core.SOARConnectorAuthHMAC:
	default:
		return core.SOARConnector{}, fmt.Errorf("%w: unsupported connector authentication", ErrInvalidConnector)
	}
	if draft.SecretRef != "" {
		if err := validateConnectorSecretRef(draft.SecretRef); err != nil {
			return core.SOARConnector{}, err
		}
	}
	actions, err := normalizeConnectorActions(draft.AllowedActions)
	if err != nil {
		return core.SOARConnector{}, err
	}
	settings, err := normalizeConnectorSettings(draft.Settings)
	if err != nil {
		return core.SOARConnector{}, err
	}
	if draft.TimeoutSeconds == 0 {
		draft.TimeoutSeconds = 10
	}
	if draft.TimeoutSeconds < 1 || draft.TimeoutSeconds > 60 {
		return core.SOARConnector{}, fmt.Errorf("%w: timeout_seconds must be between 1 and 60", ErrInvalidConnector)
	}
	if draft.Retry.MaximumAttempts == 0 {
		draft.Retry = core.SOARRetryPolicy{MaximumAttempts: 3, BackoffSeconds: 1, MaximumBackoff: 30}
	}
	if draft.Retry.MaximumAttempts < 1 || draft.Retry.MaximumAttempts > 5 ||
		draft.Retry.BackoffSeconds < 1 || draft.Retry.BackoffSeconds > 60 ||
		draft.Retry.MaximumBackoff < draft.Retry.BackoffSeconds || draft.Retry.MaximumBackoff > 300 {
		return core.SOARConnector{}, fmt.Errorf("%w: connector retry policy exceeds safe bounds", ErrInvalidConnector)
	}
	if draft.RateLimitPerMinute == 0 {
		draft.RateLimitPerMinute = 60
	}
	if draft.RateLimitPerMinute < 1 || draft.RateLimitPerMinute > 600 {
		return core.SOARConnector{}, fmt.Errorf("%w: rate_limit_per_minute must be between 1 and 600", ErrInvalidConnector)
	}
	state := core.SOARConnectorConfigured
	health := core.SOARConnectorHealthUnknown
	if draft.AuthType != core.SOARConnectorAuthNone {
		state = core.SOARConnectorCredentialsNeeded
		health = core.SOARConnectorHealthCredentials
	}
	return core.SOARConnector{
		Name: draft.Name, Kind: draft.Kind, State: state, Endpoint: endpoint.String(), AuthType: draft.AuthType,
		SecretRef: draft.SecretRef, AllowedActions: actions, Settings: settings, TimeoutSeconds: draft.TimeoutSeconds,
		Retry: draft.Retry, RateLimitPerMinute: draft.RateLimitPerMinute, HealthStatus: health,
	}, nil
}

func normalizeConnectorActions(values []string) ([]string, error) {
	allowed := map[string]bool{"kcsp.ticket.create": true, "kcsp.notification.send": true}
	unique := map[string]bool{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if !allowed[value] {
			return nil, fmt.Errorf("%w: WEBHOOK connectors only support registered A1/A2 actions", ErrInvalidConnector)
		}
		unique[value] = true
	}
	if len(unique) == 0 {
		return nil, fmt.Errorf("%w: at least one allowed action is required", ErrInvalidConnector)
	}
	result := make([]string, 0, len(unique))
	for value := range unique {
		result = append(result, value)
	}
	sort.Strings(result)
	return result, nil
}

func normalizeConnectorSettings(settings map[string]interface{}) (map[string]interface{}, error) {
	if settings == nil {
		settings = map[string]interface{}{}
	}
	result := map[string]interface{}{"health_method": "HEAD", "expected_status": 200}
	for key, value := range settings {
		switch key {
		case "health_method":
			method, ok := value.(string)
			method = strings.ToUpper(strings.TrimSpace(method))
			if !ok || (method != "HEAD" && method != "GET") {
				return nil, fmt.Errorf("%w: health_method must be HEAD or GET", ErrInvalidConnector)
			}
			result[key] = method
		case "health_path":
			path, ok := value.(string)
			if !ok || len(path) > 512 || (path != "" && (!strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//"))) {
				return nil, fmt.Errorf("%w: health_path must be an absolute URL path", ErrInvalidConnector)
			}
			result[key] = path
		case "expected_status":
			status, ok := configInt(settings, key)
			if !ok || status < 100 || status > 599 {
				return nil, fmt.Errorf("%w: expected_status must be a valid HTTP status", ErrInvalidConnector)
			}
			result[key] = status
		default:
			return nil, fmt.Errorf("%w: unsupported or secret-bearing connector setting %q", ErrInvalidConnector, key)
		}
	}
	payload, err := json.Marshal(result)
	if err != nil || len(payload) > 16<<10 {
		return nil, fmt.Errorf("%w: connector settings exceed safe bounds", ErrInvalidConnector)
	}
	return result, nil
}

func validateConnectorSecretRef(reference string) error {
	parsed, err := url.Parse(reference)
	if err != nil || parsed.User != nil || parsed.RawQuery != "" {
		return fmt.Errorf("%w: malformed secret_ref", ErrInvalidConnector)
	}
	switch parsed.Scheme {
	case "env":
		name := strings.Trim(strings.TrimPrefix(reference, "env://"), "/")
		if !secretEnvironmentName.MatchString(name) {
			return fmt.Errorf("%w: env secret refs must use KCSP_CONNECTOR_SECRET_* names", ErrInvalidConnector)
		}
	case "vault", "k8s":
		if parsed.Host == "" || strings.Trim(parsed.Path, "/") == "" {
			return fmt.Errorf("%w: secret provider ref requires a mount/namespace and path", ErrInvalidConnector)
		}
	default:
		return fmt.Errorf("%w: secret_ref must use env://, vault://, or k8s://", ErrInvalidConnector)
	}
	return nil
}

func (s *Service) connectorControlStore() (ConnectorControlStore, error) {
	repository, ok := s.store.(ConnectorControlStore)
	if !ok {
		return nil, fmt.Errorf("%w: durable connector control is unavailable", ErrInvalidState)
	}
	return repository, nil
}
