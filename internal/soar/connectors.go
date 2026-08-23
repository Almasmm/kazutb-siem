package soar

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"regexp"
	"sort"
	"strings"

	goldap "github.com/go-ldap/ldap/v3"
	"github.com/kcsp/platform/internal/core"
)

var (
	ErrInvalidConnector     = errors.New("invalid SOAR connector")
	ErrConnectorRateLimited = errors.New("SOAR connector rate limit exceeded")
)

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
var connectorHeaderName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]{0,63}$`)
var connectorHELOName = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)
var connectorLDAPAttribute = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]{0,63}$`)
var connectorJIRAProjectKey = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,31}$`)
var connectorJIRATransitionID = regexp.MustCompile(`^[0-9]{1,20}$`)
var connectorSlackChannelID = regexp.MustCompile(`^[A-Za-z0-9_-]{2,80}$`)
var connectorTeamsTeamID = regexp.MustCompile(`^[A-Za-z0-9._:-]{2,200}$`)
var connectorTeamsChannelID = regexp.MustCompile(`^[A-Za-z0-9._:@-]{2,300}$`)

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
	if _, ok := connectorProfileFor(filter.Kind); filter.Kind != "" && !ok {
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
	profile, kindSupported := connectorProfileFor(draft.Kind)
	if len(draft.Name) < 2 || len(draft.Name) > 160 || !kindSupported {
		return core.SOARConnector{}, fmt.Errorf("%w: a 2-160 character name and supported connector kind are required", ErrInvalidConnector)
	}
	endpoint, err := url.Parse(draft.Endpoint)
	if err != nil || !profile.EndpointSchemes[strings.ToLower(endpoint.Scheme)] || endpoint.Host == "" || endpoint.User != nil ||
		endpoint.Fragment != "" || endpoint.RawQuery != "" {
		return core.SOARConnector{}, fmt.Errorf("%w: endpoint scheme is unsupported or URL contains credentials, query, or fragment", ErrInvalidConnector)
	}
	if (strings.EqualFold(endpoint.Scheme, "smtps") || strings.EqualFold(endpoint.Scheme, "ldaps")) &&
		endpoint.Path != "" && endpoint.Path != "/" {
		return core.SOARConnector{}, fmt.Errorf("%w: native protocol endpoint must not contain a path", ErrInvalidConnector)
	}
	switch draft.AuthType {
	case core.SOARConnectorAuthNone, core.SOARConnectorAuthBearer, core.SOARConnectorAuthHMAC,
		core.SOARConnectorAuthBasic, core.SOARConnectorAuthAPIKey,
		core.SOARConnectorAuthOAuth2ClientCredentials:
	default:
		return core.SOARConnector{}, fmt.Errorf("%w: unsupported connector authentication", ErrInvalidConnector)
	}
	if !profile.AuthTypes[draft.AuthType] {
		return core.SOARConnector{}, fmt.Errorf("%w: authentication type is unsupported by this connector kind", ErrInvalidConnector)
	}
	if draft.AuthType == core.SOARConnectorAuthNone && !profile.AllowAnonymous {
		return core.SOARConnector{}, fmt.Errorf("%w: this connector kind requires bound authentication", ErrInvalidConnector)
	}
	if draft.SecretRef != "" {
		if err := validateConnectorSecretRef(draft.SecretRef); err != nil {
			return core.SOARConnector{}, err
		}
	}
	actions, err := normalizeConnectorActions(draft.Kind, draft.AllowedActions)
	if err != nil {
		return core.SOARConnector{}, err
	}
	settings, err := normalizeConnectorSettings(draft.Kind, draft.AuthType, draft.Settings)
	if err != nil {
		return core.SOARConnector{}, err
	}
	if err := validateNativeEDRConnectorConfiguration(draft.Kind, draft.AuthType, endpoint, settings); err != nil {
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

func normalizeConnectorActions(kind string, values []string) ([]string, error) {
	profile, ok := connectorProfileFor(kind)
	if !ok {
		return nil, fmt.Errorf("%w: unsupported connector kind", ErrInvalidConnector)
	}
	unique := map[string]bool{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if !profile.Actions[value] {
			return nil, fmt.Errorf("%w: action %q is unsupported by %s connectors", ErrInvalidConnector, value, kind)
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

func normalizeConnectorSettings(kind, authType string, settings map[string]interface{}) (map[string]interface{}, error) {
	if settings == nil {
		settings = map[string]interface{}{}
	}
	result := map[string]interface{}{}
	if kind != core.SOARConnectorKindEmailSMTP && kind != core.SOARConnectorKindLDAPDirectory {
		result["health_method"] = "HEAD"
		result["expected_status"] = 200
	}
	if kind == core.SOARConnectorKindNotification {
		result["provider"] = "GENERIC"
	}
	if kind == core.SOARConnectorKindITSMREST {
		result["provider"] = "GENERIC"
	}
	if kind == core.SOARConnectorKindEDRXDRREST {
		result["provider"] = edrXDRProviderGeneric
	}
	if kind == core.SOARConnectorKindLDAPDirectory {
		result["directory_type"] = "LDAP"
	}
	for key, value := range settings {
		switch key {
		case "health_method":
			method, ok := value.(string)
			method = strings.ToUpper(strings.TrimSpace(method))
			if !ok || kind == core.SOARConnectorKindEmailSMTP || kind == core.SOARConnectorKindLDAPDirectory || (method != "HEAD" && method != "GET") {
				return nil, fmt.Errorf("%w: health_method must be HEAD or GET", ErrInvalidConnector)
			}
			result[key] = method
		case "health_path":
			path, ok := value.(string)
			if !ok || kind == core.SOARConnectorKindEmailSMTP || kind == core.SOARConnectorKindLDAPDirectory || len(path) > 512 || (path != "" && (!strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//"))) {
				return nil, fmt.Errorf("%w: health_path must be an absolute URL path", ErrInvalidConnector)
			}
			result[key] = path
		case "expected_status":
			status, ok := configInt(settings, key)
			if !ok || kind == core.SOARConnectorKindEmailSMTP || kind == core.SOARConnectorKindLDAPDirectory || status < 100 || status > 599 {
				return nil, fmt.Errorf("%w: expected_status must be a valid HTTP status", ErrInvalidConnector)
			}
			result[key] = status
		case "api_key_header":
			header, ok := value.(string)
			header = strings.TrimSpace(header)
			if !ok || authType != core.SOARConnectorAuthAPIKey || !connectorHeaderName.MatchString(header) || forbiddenConnectorHeader(header) {
				return nil, fmt.Errorf("%w: api_key_header is invalid or unavailable for this auth type", ErrInvalidConnector)
			}
			result[key] = header
		case "provider":
			provider, ok := value.(string)
			provider = strings.ToUpper(strings.TrimSpace(provider))
			if !ok {
				return nil, fmt.Errorf("%w: connector provider is invalid", ErrInvalidConnector)
			}
			switch kind {
			case core.SOARConnectorKindNotification:
				if provider != "GENERIC" && provider != "SLACK" && provider != "TEAMS" &&
					provider != notificationProviderSlackWebAPI && provider != notificationProviderTeamsGraph {
					return nil, fmt.Errorf("%w: notification provider is unsupported", ErrInvalidConnector)
				}
			case core.SOARConnectorKindITSMREST:
				if provider != "GENERIC" && provider != "SERVICENOW" && provider != "JIRA" {
					return nil, fmt.Errorf("%w: ITSM provider must be GENERIC, SERVICENOW, or JIRA", ErrInvalidConnector)
				}
			case core.SOARConnectorKindEDRXDRREST:
				if provider != edrXDRProviderGeneric && provider != edrXDRProviderMicrosoftDefender &&
					provider != edrXDRProviderCrowdStrikeFalcon {
					return nil, fmt.Errorf("%w: EDR/XDR provider is unsupported", ErrInvalidConnector)
				}
			default:
				return nil, fmt.Errorf("%w: provider is unavailable for this connector kind", ErrInvalidConnector)
			}
			result[key] = provider
		case "project_key":
			projectKey, ok := value.(string)
			projectKey = strings.ToUpper(strings.TrimSpace(projectKey))
			if !ok || kind != core.SOARConnectorKindITSMREST || !connectorJIRAProjectKey.MatchString(projectKey) {
				return nil, fmt.Errorf("%w: Jira project_key is invalid", ErrInvalidConnector)
			}
			result[key] = projectKey
		case "issue_type":
			issueType, ok := value.(string)
			issueType = strings.TrimSpace(issueType)
			if !ok || kind != core.SOARConnectorKindITSMREST || issueType == "" || len(issueType) > 120 || strings.ContainsAny(issueType, "\x00\r\n") {
				return nil, fmt.Errorf("%w: Jira issue_type is invalid", ErrInvalidConnector)
			}
			result[key] = issueType
		case "close_transition_id":
			transitionID, ok := value.(string)
			transitionID = strings.TrimSpace(transitionID)
			if !ok || kind != core.SOARConnectorKindITSMREST || !connectorJIRATransitionID.MatchString(transitionID) {
				return nil, fmt.Errorf("%w: Jira close_transition_id is invalid", ErrInvalidConnector)
			}
			result[key] = transitionID
		case "channel":
			channel, ok := value.(string)
			channel = strings.TrimSpace(channel)
			if !ok || kind != core.SOARConnectorKindNotification || channel == "" || len(channel) > 200 || strings.ContainsAny(channel, "\r\n") {
				return nil, fmt.Errorf("%w: notification channel is invalid", ErrInvalidConnector)
			}
			result[key] = channel
		case "team_id":
			teamID, ok := value.(string)
			teamID = strings.TrimSpace(teamID)
			if !ok || kind != core.SOARConnectorKindNotification || !connectorTeamsTeamID.MatchString(teamID) {
				return nil, fmt.Errorf("%w: Microsoft Teams team_id is invalid", ErrInvalidConnector)
			}
			result[key] = teamID
		case "channel_id":
			channelID, ok := value.(string)
			channelID = strings.TrimSpace(channelID)
			if !ok || kind != core.SOARConnectorKindNotification || !connectorTeamsChannelID.MatchString(channelID) {
				return nil, fmt.Errorf("%w: Microsoft Teams channel_id is invalid", ErrInvalidConnector)
			}
			result[key] = channelID
		case "from_address":
			from, ok := value.(string)
			address, err := mail.ParseAddress(strings.TrimSpace(from))
			if !ok || err != nil || kind != core.SOARConnectorKindEmailSMTP || address.Address == "" || len(address.Address) > 320 {
				return nil, fmt.Errorf("%w: SMTP from_address is invalid", ErrInvalidConnector)
			}
			result[key] = address.Address
		case "helo_name":
			helo, ok := value.(string)
			helo = strings.TrimSpace(helo)
			if !ok || kind != core.SOARConnectorKindEmailSMTP || !connectorHELOName.MatchString(helo) {
				return nil, fmt.Errorf("%w: SMTP helo_name is invalid", ErrInvalidConnector)
			}
			result[key] = helo
		case "directory_type":
			directoryType, ok := value.(string)
			directoryType = strings.ToUpper(strings.TrimSpace(directoryType))
			if !ok || kind != core.SOARConnectorKindLDAPDirectory || (directoryType != "LDAP" && directoryType != "ACTIVE_DIRECTORY") {
				return nil, fmt.Errorf("%w: directory_type must be LDAP or ACTIVE_DIRECTORY", ErrInvalidConnector)
			}
			result[key] = directoryType
		case "base_dn":
			baseDN, ok := value.(string)
			parsed, err := goldap.ParseDN(strings.TrimSpace(baseDN))
			if !ok || err != nil || kind != core.SOARConnectorKindLDAPDirectory || len(parsed.RDNs) == 0 || len(parsed.String()) > 2048 {
				return nil, fmt.Errorf("%w: LDAP base_dn is invalid", ErrInvalidConnector)
			}
			result[key] = parsed.String()
		case "account_attribute", "disabled_attribute":
			attribute, ok := value.(string)
			attribute = strings.TrimSpace(attribute)
			if !ok || kind != core.SOARConnectorKindLDAPDirectory || !connectorLDAPAttribute.MatchString(attribute) {
				return nil, fmt.Errorf("%w: LDAP attribute name is invalid", ErrInvalidConnector)
			}
			result[key] = attribute
		case "disabled_value", "enabled_value":
			directoryValue, ok := value.(string)
			if !ok || kind != core.SOARConnectorKindLDAPDirectory || len(directoryValue) > 512 || strings.ContainsAny(directoryValue, "\x00\r\n") || (key == "disabled_value" && directoryValue == "") {
				return nil, fmt.Errorf("%w: LDAP account state value is invalid", ErrInvalidConnector)
			}
			result[key] = directoryValue
		default:
			return nil, fmt.Errorf("%w: unsupported or secret-bearing connector setting %q", ErrInvalidConnector, key)
		}
	}
	if authType == core.SOARConnectorAuthAPIKey {
		if _, ok := result["api_key_header"]; !ok {
			result["api_key_header"] = "X-API-Key"
		}
	}
	if kind == core.SOARConnectorKindNotification {
		provider, _ := result["provider"].(string)
		if (provider == "SLACK" || provider == notificationProviderSlackWebAPI) && result["channel"] == nil {
			return nil, fmt.Errorf("%w: Slack notification connectors require a channel", ErrInvalidConnector)
		}
		if provider == notificationProviderSlackWebAPI {
			channel, _ := result["channel"].(string)
			if authType != core.SOARConnectorAuthBearer || !connectorSlackChannelID.MatchString(channel) {
				return nil, fmt.Errorf("%w: native Slack requires BEARER auth and a conversation ID", ErrInvalidConnector)
			}
		}
		if provider == notificationProviderTeamsGraph {
			if authType != core.SOARConnectorAuthBearer || result["team_id"] == nil || result["channel_id"] == nil {
				return nil, fmt.Errorf("%w: native Teams Graph requires BEARER auth, team_id, and channel_id", ErrInvalidConnector)
			}
		}
	}
	if kind == core.SOARConnectorKindITSMREST {
		provider, _ := result["provider"].(string)
		if provider == "JIRA" {
			if result["project_key"] == nil {
				return nil, fmt.Errorf("%w: Jira connectors require project_key", ErrInvalidConnector)
			}
			if result["issue_type"] == nil {
				result["issue_type"] = "Task"
			}
		} else {
			for _, key := range []string{"project_key", "issue_type", "close_transition_id"} {
				if _, configured := settings[key]; configured {
					return nil, fmt.Errorf("%w: %s is available only for Jira connectors", ErrInvalidConnector, key)
				}
			}
		}
	}
	if kind == core.SOARConnectorKindEDRXDRREST {
		provider, _ := result["provider"].(string)
		if provider == edrXDRProviderGeneric && authType == core.SOARConnectorAuthOAuth2ClientCredentials {
			return nil, fmt.Errorf("%w: OAuth2 client credentials are available only for native EDR/XDR providers", ErrInvalidConnector)
		}
		if provider != edrXDRProviderGeneric && authType != core.SOARConnectorAuthOAuth2ClientCredentials {
			return nil, fmt.Errorf("%w: native EDR/XDR providers require OAUTH2_CLIENT_CREDENTIALS", ErrInvalidConnector)
		}
	}
	if kind == core.SOARConnectorKindEmailSMTP && result["from_address"] == nil {
		return nil, fmt.Errorf("%w: SMTP connectors require from_address", ErrInvalidConnector)
	}
	if kind == core.SOARConnectorKindLDAPDirectory {
		if result["base_dn"] == nil {
			return nil, fmt.Errorf("%w: LDAP connectors require base_dn", ErrInvalidConnector)
		}
		directoryType, _ := result["directory_type"].(string)
		if result["account_attribute"] == nil {
			if directoryType == "ACTIVE_DIRECTORY" {
				result["account_attribute"] = "sAMAccountName"
			} else {
				result["account_attribute"] = "uid"
			}
		}
		if directoryType == "ACTIVE_DIRECTORY" {
			for _, key := range []string{"disabled_attribute", "disabled_value", "enabled_value"} {
				if _, configured := settings[key]; configured {
					return nil, fmt.Errorf("%w: Active Directory account state uses userAccountControl", ErrInvalidConnector)
				}
			}
		} else {
			if result["disabled_attribute"] == nil {
				result["disabled_attribute"] = "pwdAccountLockedTime"
			}
			if result["disabled_value"] == nil {
				result["disabled_value"] = "000001010000Z"
			}
			if result["enabled_value"] == nil {
				result["enabled_value"] = ""
			}
		}
	}
	payload, err := json.Marshal(result)
	if err != nil || len(payload) > 16<<10 {
		return nil, fmt.Errorf("%w: connector settings exceed safe bounds", ErrInvalidConnector)
	}
	return result, nil
}

func forbiddenConnectorHeader(value string) bool {
	switch strings.ToLower(value) {
	case "host", "content-length", "connection", "cookie", "set-cookie", "transfer-encoding",
		"proxy-authorization", "proxy-authenticate", "idempotency-key", "x-kcsp-connector-id":
		return true
	default:
		return strings.HasPrefix(strings.ToLower(value), "x-kcsp-")
	}
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
