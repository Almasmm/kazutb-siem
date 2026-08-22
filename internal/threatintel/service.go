package threatintel

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/kcsp/platform/internal/core"
)

var (
	ErrInvalidFeed      = errors.New("invalid threat intelligence feed")
	ErrInvalidIndicator = errors.New("invalid threat indicator")
)

const maximumIndicatorTTL = int64((10 * 365 * 24 * time.Hour) / time.Second)

type Store interface {
	CreateThreatIntelFeed(context.Context, core.ThreatIntelFeed) (core.ThreatIntelFeed, error)
	GetThreatIntelFeed(context.Context, string, string) (core.ThreatIntelFeed, error)
	ListThreatIntelFeeds(context.Context, string) ([]core.ThreatIntelFeed, error)
	UpdateThreatIntelFeed(context.Context, core.ThreatIntelFeed) (core.ThreatIntelFeed, error)
	UpsertThreatIndicator(context.Context, core.ThreatIndicator) (core.ThreatIndicator, bool, error)
	GetThreatIndicator(context.Context, string, string) (core.ThreatIndicator, error)
	ListThreatIndicators(context.Context, string, core.ThreatIndicatorFilter) ([]core.ThreatIndicator, error)
	SetThreatIndicatorState(context.Context, string, string, string, int, string) (core.ThreatIndicator, error)
	ListThreatIntelMatches(context.Context, string, string, string, int) ([]core.ThreatIntelMatch, error)
}

type Service struct {
	store Store
	now   func() time.Time
}

type FeedDraft struct {
	Name                   string   `json:"name"`
	Kind                   string   `json:"kind"`
	Description            string   `json:"description,omitempty"`
	SourceURL              string   `json:"source_url,omitempty"`
	AuthReference          string   `json:"auth_reference,omitempty"`
	RefreshIntervalSeconds int      `json:"refresh_interval_seconds,omitempty"`
	DefaultConfidence      int      `json:"default_confidence,omitempty"`
	Tags                   []string `json:"tags,omitempty"`
}

type FeedPatch struct {
	Name                   *string   `json:"name,omitempty"`
	Description            *string   `json:"description,omitempty"`
	State                  *string   `json:"state,omitempty"`
	SourceURL              *string   `json:"source_url,omitempty"`
	AuthReference          *string   `json:"auth_reference,omitempty"`
	RefreshIntervalSeconds *int      `json:"refresh_interval_seconds,omitempty"`
	DefaultConfidence      *int      `json:"default_confidence,omitempty"`
	Tags                   *[]string `json:"tags,omitempty"`
	Version                int       `json:"version"`
}

type IndicatorDraft struct {
	FeedID       string                   `json:"feed_id"`
	Type         core.ThreatIndicatorType `json:"type"`
	Value        string                   `json:"value"`
	Source       string                   `json:"source,omitempty"`
	Confidence   *int                     `json:"confidence,omitempty"`
	Reputation   string                   `json:"reputation,omitempty"`
	TTLSeconds   int64                    `json:"ttl_seconds,omitempty"`
	FirstSeen    time.Time                `json:"first_seen,omitempty"`
	LastSeen     time.Time                `json:"last_seen,omitempty"`
	ValidFrom    time.Time                `json:"valid_from,omitempty"`
	ValidUntil   *time.Time               `json:"valid_until,omitempty"`
	Tags         []string                 `json:"tags,omitempty"`
	Campaign     string                   `json:"campaign,omitempty"`
	Malware      string                   `json:"malware,omitempty"`
	ThreatActors []string                 `json:"threat_actors,omitempty"`
	Description  string                   `json:"description,omitempty"`
	ExternalID   string                   `json:"external_id,omitempty"`
}

func NewService(store Store) *Service {
	return &Service{store: store, now: func() time.Time { return time.Now().UTC() }}
}

func (s *Service) CreateFeed(ctx context.Context, tenantID, actor string, draft FeedDraft) (core.ThreatIntelFeed, error) {
	now := s.now()
	feed := core.ThreatIntelFeed{
		ID: core.NewID("tif"), TenantID: strings.TrimSpace(tenantID), Name: strings.TrimSpace(draft.Name),
		Kind: strings.ToUpper(strings.TrimSpace(draft.Kind)), Description: strings.TrimSpace(draft.Description),
		State: core.ThreatIntelStateActive, SourceURL: strings.TrimSpace(draft.SourceURL),
		AuthReference: strings.TrimSpace(draft.AuthReference), RefreshIntervalSeconds: draft.RefreshIntervalSeconds,
		DefaultConfidence: draft.DefaultConfidence, Tags: normalizeList(draft.Tags, 50, 64),
		Version: 1, CreatedBy: actor, UpdatedBy: actor, CreatedAt: now, UpdatedAt: now,
	}
	if feed.Kind == "" {
		feed.Kind = "MANUAL"
	}
	if feed.RefreshIntervalSeconds == 0 && feed.Kind != "MANUAL" {
		feed.RefreshIntervalSeconds = 3600
	}
	if feed.DefaultConfidence == 0 {
		feed.DefaultConfidence = 70
	}
	if err := validateFeed(feed); err != nil {
		return core.ThreatIntelFeed{}, err
	}
	return s.store.CreateThreatIntelFeed(ctx, feed)
}

func (s *Service) UpdateFeed(ctx context.Context, tenantID, feedID, actor string, patch FeedPatch) (core.ThreatIntelFeed, error) {
	current, err := s.store.GetThreatIntelFeed(ctx, tenantID, feedID)
	if err != nil {
		return core.ThreatIntelFeed{}, err
	}
	if patch.Version == 0 {
		return core.ThreatIntelFeed{}, fmt.Errorf("%w: version is required", ErrInvalidFeed)
	}
	current.Version = patch.Version
	if patch.Name != nil {
		current.Name = strings.TrimSpace(*patch.Name)
	}
	if patch.Description != nil {
		current.Description = strings.TrimSpace(*patch.Description)
	}
	if patch.State != nil {
		current.State = strings.ToUpper(strings.TrimSpace(*patch.State))
	}
	if patch.SourceURL != nil {
		current.SourceURL = strings.TrimSpace(*patch.SourceURL)
	}
	if patch.AuthReference != nil {
		current.AuthReference = strings.TrimSpace(*patch.AuthReference)
	}
	if patch.RefreshIntervalSeconds != nil {
		current.RefreshIntervalSeconds = *patch.RefreshIntervalSeconds
	}
	if patch.DefaultConfidence != nil {
		current.DefaultConfidence = *patch.DefaultConfidence
	}
	if patch.Tags != nil {
		current.Tags = normalizeList(*patch.Tags, 50, 64)
	}
	current.UpdatedBy = actor
	current.UpdatedAt = s.now()
	if err := validateFeed(current); err != nil {
		return core.ThreatIntelFeed{}, err
	}
	return s.store.UpdateThreatIntelFeed(ctx, current)
}

func (s *Service) Feed(ctx context.Context, tenantID, feedID string) (core.ThreatIntelFeed, error) {
	return s.store.GetThreatIntelFeed(ctx, tenantID, feedID)
}

func (s *Service) Feeds(ctx context.Context, tenantID string) ([]core.ThreatIntelFeed, error) {
	return s.store.ListThreatIntelFeeds(ctx, tenantID)
}

func (s *Service) UpsertIndicator(ctx context.Context, tenantID, actor string, draft IndicatorDraft) (core.ThreatIndicator, bool, error) {
	feed, err := s.store.GetThreatIntelFeed(ctx, tenantID, strings.TrimSpace(draft.FeedID))
	if err != nil {
		return core.ThreatIndicator{}, false, err
	}
	indicatorType, err := NormalizeIndicatorType(draft.Type)
	if err != nil {
		return core.ThreatIndicator{}, false, err
	}
	normalized, err := NormalizeValue(indicatorType, draft.Value)
	if err != nil {
		return core.ThreatIndicator{}, false, err
	}
	now := s.now()
	firstSeen := draft.FirstSeen.UTC()
	if draft.FirstSeen.IsZero() {
		firstSeen = now
	}
	lastSeen := draft.LastSeen.UTC()
	if draft.LastSeen.IsZero() {
		lastSeen = firstSeen
	}
	validFrom := draft.ValidFrom.UTC()
	if draft.ValidFrom.IsZero() {
		validFrom = firstSeen
	}
	validUntil := draft.ValidUntil
	if validUntil != nil {
		utc := validUntil.UTC()
		validUntil = &utc
	}
	if draft.TTLSeconds < 0 || draft.TTLSeconds > maximumIndicatorTTL {
		return core.ThreatIndicator{}, false, fmt.Errorf("%w: ttl_seconds must be between 0 and %d", ErrInvalidIndicator, maximumIndicatorTTL)
	}
	if validUntil == nil && draft.TTLSeconds > 0 {
		expires := lastSeen.Add(time.Duration(draft.TTLSeconds) * time.Second)
		validUntil = &expires
	}
	if firstSeen.After(lastSeen) || validFrom.After(lastSeen) || (validUntil != nil && !validUntil.After(validFrom)) {
		return core.ThreatIndicator{}, false, fmt.Errorf("%w: invalid first_seen, last_seen, or validity window", ErrInvalidIndicator)
	}
	confidence := feed.DefaultConfidence
	if draft.Confidence != nil {
		confidence = *draft.Confidence
	}
	reputation := strings.ToUpper(strings.TrimSpace(draft.Reputation))
	if reputation == "" {
		reputation = "UNKNOWN"
	}
	source := strings.TrimSpace(draft.Source)
	if source == "" {
		source = feed.Name
	}
	indicator := core.ThreatIndicator{
		ID: core.NewID("ioc"), TenantID: tenantID, FeedID: feed.ID, Type: indicatorType,
		Value: strings.TrimSpace(draft.Value), NormalizedValue: normalized, Source: source,
		Confidence: confidence, Reputation: reputation, TTLSeconds: draft.TTLSeconds,
		FirstSeen: firstSeen, LastSeen: lastSeen, ValidFrom: validFrom, ValidUntil: validUntil,
		Tags: normalizeList(draft.Tags, 50, 64), Campaign: strings.TrimSpace(draft.Campaign),
		Malware: strings.TrimSpace(draft.Malware), ThreatActors: normalizeList(draft.ThreatActors, 50, 128),
		Description: strings.TrimSpace(draft.Description), ExternalID: strings.TrimSpace(draft.ExternalID),
		State: core.ThreatIntelStateActive, Version: 1, CreatedBy: actor, UpdatedBy: actor,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := validateIndicator(indicator); err != nil {
		return core.ThreatIndicator{}, false, err
	}
	return s.store.UpsertThreatIndicator(ctx, indicator)
}

func (s *Service) Indicator(ctx context.Context, tenantID, indicatorID string) (core.ThreatIndicator, error) {
	return s.store.GetThreatIndicator(ctx, tenantID, indicatorID)
}

func (s *Service) Indicators(ctx context.Context, tenantID string, filter core.ThreatIndicatorFilter) ([]core.ThreatIndicator, error) {
	if filter.Limit <= 0 {
		filter.Limit = 100
	}
	if filter.Limit > 500 {
		filter.Limit = 500
	}
	filter.State = strings.ToUpper(strings.TrimSpace(filter.State))
	if filter.Type != "" {
		indicatorType, err := NormalizeIndicatorType(filter.Type)
		if err != nil {
			return nil, err
		}
		filter.Type = indicatorType
	}
	return s.store.ListThreatIndicators(ctx, tenantID, filter)
}

func (s *Service) SetIndicatorState(ctx context.Context, tenantID, indicatorID, actor, state string, version int) (core.ThreatIndicator, error) {
	state = strings.ToUpper(strings.TrimSpace(state))
	if state != core.ThreatIntelStateActive && state != core.ThreatIntelStateRevoked {
		return core.ThreatIndicator{}, fmt.Errorf("%w: state must be ACTIVE or REVOKED", ErrInvalidIndicator)
	}
	if version < 1 {
		return core.ThreatIndicator{}, fmt.Errorf("%w: version is required", ErrInvalidIndicator)
	}
	return s.store.SetThreatIndicatorState(ctx, tenantID, indicatorID, state, version, actor)
}

func (s *Service) Matches(ctx context.Context, tenantID, indicatorID, eventID string, limit int) ([]core.ThreatIntelMatch, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	return s.store.ListThreatIntelMatches(ctx, tenantID, indicatorID, strings.TrimSpace(eventID), limit)
}

func validateFeed(feed core.ThreatIntelFeed) error {
	if feed.TenantID == "" || feed.CreatedBy == "" || len(feed.Name) < 2 || len(feed.Name) > 160 {
		return fmt.Errorf("%w: tenant, actor, and a 2-160 character name are required", ErrInvalidFeed)
	}
	switch feed.Kind {
	case "MANUAL", "CUSTOM", "STIX", "TAXII", "MISP", "OPENCTI":
	default:
		return fmt.Errorf("%w: unsupported feed kind %q", ErrInvalidFeed, feed.Kind)
	}
	if feed.State != core.ThreatIntelStateActive && feed.State != core.ThreatIntelStateDisabled {
		return fmt.Errorf("%w: state must be ACTIVE or DISABLED", ErrInvalidFeed)
	}
	if feed.DefaultConfidence < 0 || feed.DefaultConfidence > 100 {
		return fmt.Errorf("%w: default_confidence must be between 0 and 100", ErrInvalidFeed)
	}
	if feed.RefreshIntervalSeconds < 0 || feed.RefreshIntervalSeconds > 604800 ||
		(feed.RefreshIntervalSeconds > 0 && feed.RefreshIntervalSeconds < 60) {
		return fmt.Errorf("%w: refresh interval must be 0 or between 60 and 604800 seconds", ErrInvalidFeed)
	}
	if len(feed.Description) > 2000 || len(feed.AuthReference) > 500 {
		return fmt.Errorf("%w: description or auth reference is too long", ErrInvalidFeed)
	}
	if feed.SourceURL != "" {
		parsed, err := url.Parse(feed.SourceURL)
		if err != nil || parsed.Host == "" || parsed.User != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") {
			return fmt.Errorf("%w: source_url must be an http(s) URL without embedded credentials", ErrInvalidFeed)
		}
	}
	return nil
}

func validateIndicator(indicator core.ThreatIndicator) error {
	if indicator.TenantID == "" || indicator.FeedID == "" || indicator.Source == "" || indicator.CreatedBy == "" {
		return fmt.Errorf("%w: tenant, feed, source, and actor are required", ErrInvalidIndicator)
	}
	if indicator.Confidence < 0 || indicator.Confidence > 100 {
		return fmt.Errorf("%w: confidence must be between 0 and 100", ErrInvalidIndicator)
	}
	switch indicator.Reputation {
	case "MALICIOUS", "SUSPICIOUS", "UNKNOWN", "TRUSTED":
	default:
		return fmt.Errorf("%w: unsupported reputation %q", ErrInvalidIndicator, indicator.Reputation)
	}
	for name, value := range map[string]string{
		"source": indicator.Source, "campaign": indicator.Campaign, "malware": indicator.Malware,
		"description": indicator.Description, "external_id": indicator.ExternalID,
	} {
		limit := 500
		if name == "description" {
			limit = 4000
		}
		if len(value) > limit {
			return fmt.Errorf("%w: %s is too long", ErrInvalidIndicator, name)
		}
	}
	return nil
}

func normalizeList(values []string, maximum, maximumLength int) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || len(value) > maximumLength {
			continue
		}
		key := strings.ToLower(value)
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, value)
		if len(result) == maximum {
			break
		}
	}
	sort.Strings(result)
	return result
}
