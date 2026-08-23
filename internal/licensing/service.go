package licensing

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/platform/tenant"
)

var (
	ErrInvalidLicense      = errors.New("invalid license")
	ErrUntrustedKey        = errors.New("untrusted license signing key")
	ErrModuleNotEntitled   = errors.New("module is not entitled")
	ErrLicenseRestricted   = errors.New("license is read-only or expired")
	ErrQuotaExceeded       = errors.New("licensed quota exceeded")
	ErrTenantSuspended     = errors.New("tenant is suspended")
	ErrTenantLimitExceeded = errors.New("licensed tenant limit exceeded")
)

type Repository interface {
	CurrentLicense(context.Context, string) (core.LicenseRecord, bool, error)
	InstallLicense(context.Context, core.LicenseRecord) (core.LicenseRecord, bool, error)
	ListLicenses(context.Context, string) ([]core.LicenseRecord, error)
	ListTenants(context.Context) ([]core.Tenant, error)
	GetTenant(context.Context, string) (core.Tenant, error)
	CreateTenant(context.Context, core.Tenant) (core.Tenant, error)
	SetTenantState(context.Context, string, string) (core.Tenant, error)
	Overview(context.Context, string) (map[string]interface{}, error)
}

type Config struct {
	Profile     string
	TrustedKeys map[string]ed25519.PublicKey
	Now         func() time.Time
}

type Service struct {
	repository  Repository
	profile     string
	trustedKeys map[string]ed25519.PublicKey
	now         func() time.Time
}

type InstallInput struct {
	Envelope  core.LicenseEnvelope `json:"envelope"`
	RequestID string               `json:"request_id,omitempty"`
}

type TenantInput struct {
	ID          string `json:"tenant_id"`
	DisplayName string `json:"display_name"`
}

func NewService(repository Repository, config Config) *Service {
	now := config.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	keys := make(map[string]ed25519.PublicKey, len(config.TrustedKeys))
	for id, key := range config.TrustedKeys {
		keys[id] = append(ed25519.PublicKey(nil), key...)
	}
	return &Service{repository: repository, profile: strings.ToLower(strings.TrimSpace(config.Profile)), trustedKeys: keys, now: now}
}

func ParseTrustedKeysJSON(value string) (map[string]ed25519.PublicKey, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return map[string]ed25519.PublicKey{}, nil
	}
	var encoded map[string]string
	if err := json.Unmarshal([]byte(value), &encoded); err != nil {
		return nil, fmt.Errorf("decode KCSP_LICENSE_TRUSTED_KEYS_JSON: %w", err)
	}
	keys := make(map[string]ed25519.PublicKey, len(encoded))
	for id, raw := range encoded {
		id = strings.TrimSpace(id)
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(raw))
		if err != nil {
			decoded, err = base64.RawURLEncoding.DecodeString(strings.TrimSpace(raw))
		}
		if id == "" || err != nil || len(decoded) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid Ed25519 public key %q", id)
		}
		keys[id] = ed25519.PublicKey(decoded)
	}
	return keys, nil
}

func (s *Service) Install(ctx context.Context, tenantID, actor string, input InstallInput) (core.LicenseRecord, bool, error) {
	payload, fingerprint, err := s.verify(tenantID, input.Envelope)
	if err != nil {
		return core.LicenseRecord{}, false, err
	}
	record := core.LicenseRecord{
		TenantID: tenantID, LicenseID: payload.LicenseID, KeyID: input.Envelope.KeyID,
		Payload: payload, Envelope: input.Envelope, Fingerprint: fingerprint,
		InstalledBy: strings.TrimSpace(actor), RequestID: strings.TrimSpace(input.RequestID), Active: true, InstalledAt: s.now(),
	}
	return s.repository.InstallLicense(ctx, record)
}

func (s *Service) Licenses(ctx context.Context, tenantID string) ([]core.LicenseRecord, error) {
	return s.repository.ListLicenses(ctx, tenantID)
}

func (s *Service) Status(ctx context.Context, tenantID string) (core.LicenseStatus, error) {
	tenants, err := s.repository.ListTenants(ctx)
	if err != nil {
		return core.LicenseStatus{}, err
	}
	return s.status(ctx, tenantID, len(tenants))
}

func (s *Service) status(ctx context.Context, tenantID string, tenantCount int) (core.LicenseStatus, error) {
	overview, err := s.repository.Overview(ctx, tenantID)
	if err != nil {
		return core.LicenseStatus{}, err
	}
	return s.statusWithOverview(ctx, tenantID, tenantCount, overview)
}

func (s *Service) statusWithOverview(ctx context.Context, tenantID string, tenantCount int, overview map[string]interface{}) (core.LicenseStatus, error) {
	now := s.now()
	record, found, err := s.repository.CurrentLicense(ctx, tenantID)
	if err != nil {
		return core.LicenseStatus{}, err
	}
	if !found && (s.profile == "development" || s.profile == "test") {
		record = developmentLicense(tenantID, now)
		found = true
	}
	status := core.LicenseStatus{TenantID: tenantID, State: "UNLICENSED", ReadOnly: true, CheckedAt: now, Features: []string{}, Warnings: []string{"UNLICENSED"}}
	if found {
		status.License = &record
		status.State, status.ReadOnly = licenseState(record.Payload, now, strings.HasPrefix(record.LicenseID, "development-"))
		status.Features = append([]string(nil), record.Payload.Features...)
		status.Warnings = nil
		if status.State == "GRACE" {
			status.Warnings = append(status.Warnings, "GRACE")
		}
		if status.State == "EXPIRED" {
			status.Warnings = append(status.Warnings, "EXPIRED")
		}
		if status.State == "NOT_YET_VALID" {
			status.Warnings = append(status.Warnings, "NOT_YET_VALID")
		}
	}
	enabled := map[string]bool{}
	if found {
		for _, module := range record.Payload.Modules {
			enabled[module] = true
		}
	}
	for _, module := range core.LicenseModules {
		status.Modules = append(status.Modules, core.LicenseModuleStatus{Module: module, Enabled: enabled[module]})
	}
	limits := core.LicenseLimits{}
	if found {
		limits = record.Payload.Limits
	}
	status.Limits = buildLimitStatus(limits, overview, tenantCount)
	for _, limit := range status.Limits {
		if limit.Exceeded {
			status.Warnings = append(status.Warnings, "QUOTA_EXCEEDED:"+limit.Name)
		} else if limit.Limit > 0 && limit.Percent >= 80 {
			status.Warnings = append(status.Warnings, "QUOTA_WARNING:"+limit.Name)
		}
	}
	return status, nil
}

func (s *Service) Authorize(ctx context.Context, tenantID, permission, method string) error {
	module := moduleForPermission(permission)
	if module == "" {
		return nil
	}
	tenantRecord, err := s.repository.GetTenant(ctx, tenantID)
	if err != nil {
		return err
	}
	if tenantRecord.State == "SUSPENDED" {
		return ErrTenantSuspended
	}
	now := s.now()
	record, found, err := s.repository.CurrentLicense(ctx, tenantID)
	if err != nil {
		return err
	}
	if !found && (s.profile == "development" || s.profile == "test") {
		record = developmentLicense(tenantID, now)
		found = true
	}
	if !found || !contains(record.Payload.Modules, module) {
		return fmt.Errorf("%w: %s", ErrModuleNotEntitled, module)
	}
	write := method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions
	state, _ := licenseState(record.Payload, now, strings.HasPrefix(record.LicenseID, "development-"))
	if state == "NOT_YET_VALID" || state == "UNLICENSED" {
		return ErrLicenseRestricted
	}
	if state == "EXPIRED" && write {
		if permission == "siem.events.ingest" && strings.EqualFold(record.Payload.Policy.IngestAfterExpiry, "ALLOW") {
			return nil
		}
		if permission == "siem.events.ingest" || record.Payload.Policy.ReadOnlyOnExpiry {
			return ErrLicenseRestricted
		}
	}
	if write {
		overview, overviewErr := s.repository.Overview(ctx, tenantID)
		if overviewErr != nil {
			return overviewErr
		}
		tenants, tenantErr := s.repository.ListTenants(ctx)
		if tenantErr != nil {
			return tenantErr
		}
		if err := enforceQuota(permission, buildLimitStatus(record.Payload.Limits, overview, len(tenants))); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) AuthorizeIngestBatch(ctx context.Context, tenantID string, eventCount int, payloadBytes int64) error {
	if eventCount < 1 || eventCount > ingestBatchMaximum || payloadBytes < 0 {
		return fmt.Errorf("%w: invalid ingest batch dimensions", ErrQuotaExceeded)
	}
	if err := s.Authorize(ctx, tenantID, "siem.events.ingest", http.MethodPost); err != nil {
		return err
	}
	record, found, err := s.repository.CurrentLicense(ctx, tenantID)
	if err != nil {
		return err
	}
	if !found && (s.profile == "development" || s.profile == "test") {
		record = developmentLicense(tenantID, s.now())
		found = true
	}
	if !found {
		return ErrLicenseRestricted
	}
	overview, err := s.repository.Overview(ctx, tenantID)
	if err != nil {
		return err
	}
	limits := record.Payload.Limits
	if limits.EventsPerDay > 0 && numeric(overview, "events_24h")+float64(eventCount) > float64(limits.EventsPerDay) {
		return fmt.Errorf("%w: events_per_day maximum is %d", ErrQuotaExceeded, limits.EventsPerDay)
	}
	if limits.EPS > 0 && numeric(overview, "ingestion_eps", "ingest_rate_eps", "eps")+float64(eventCount) > float64(limits.EPS) {
		return fmt.Errorf("%w: eps maximum is %d", ErrQuotaExceeded, limits.EPS)
	}
	batchGB := float64(payloadBytes) / float64(1<<30)
	if limits.GBPerDay > 0 && numeric(overview, "ingested_gb_24h", "gb_24h")+batchGB > limits.GBPerDay {
		return fmt.Errorf("%w: gb_per_day maximum is %.2f", ErrQuotaExceeded, limits.GBPerDay)
	}
	return nil
}

const ingestBatchMaximum = 500

// ValidateRetention ensures every configured retention tier stays within the
// active tenant license. A zero limit means the issuer did not impose a cap.
func (s *Service) ValidateRetention(ctx context.Context, tenantID string, rawDays, normalizedDays, findingsDays, evidenceDays int) error {
	record, found, err := s.repository.CurrentLicense(ctx, tenantID)
	if err != nil {
		return err
	}
	if !found && (s.profile == "development" || s.profile == "test") {
		record = developmentLicense(tenantID, s.now())
		found = true
	}
	if !found {
		return ErrLicenseRestricted
	}

	requested := max(rawDays, normalizedDays, findingsDays, evidenceDays)
	if limit := record.Payload.Limits.RetentionDays; limit > 0 && requested > limit {
		return fmt.Errorf("%w: retention_days maximum is %d", ErrQuotaExceeded, limit)
	}
	return nil
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func (s *Service) Tenants(ctx context.Context, filter core.TenantFilter) ([]core.TenantSummary, int, error) {
	tenants, err := s.repository.ListTenants(ctx)
	if err != nil {
		return nil, 0, err
	}
	query := strings.ToLower(strings.TrimSpace(filter.Query))
	filtered := make([]core.Tenant, 0, len(tenants))
	for _, item := range tenants {
		if query == "" || strings.Contains(strings.ToLower(item.ID), query) || strings.Contains(strings.ToLower(item.DisplayName), query) {
			filtered = append(filtered, item)
		}
	}
	sort.Slice(filtered, func(i, j int) bool {
		if filtered[i].DisplayName == filtered[j].DisplayName {
			return filtered[i].ID < filtered[j].ID
		}
		return filtered[i].DisplayName < filtered[j].DisplayName
	})
	total := len(filtered)
	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}
	if offset > total {
		offset = total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	page := filtered[offset:end]
	items := make([]core.TenantSummary, len(page))
	semaphore := make(chan struct{}, 8)
	var wait sync.WaitGroup
	var errorMu sync.Mutex
	var firstErr error
	for index, item := range page {
		wait.Add(1)
		go func(index int, item core.Tenant) {
			defer wait.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			if ctx.Err() != nil {
				return
			}
			overview, overviewErr := s.repository.Overview(ctx, item.ID)
			if overviewErr != nil {
				errorMu.Lock()
				if firstErr == nil {
					firstErr = overviewErr
				}
				errorMu.Unlock()
				return
			}
			status, statusErr := s.statusWithOverview(ctx, item.ID, len(tenants), overview)
			if statusErr != nil {
				errorMu.Lock()
				if firstErr == nil {
					firstErr = statusErr
				}
				errorMu.Unlock()
				return
			}
			items[index] = core.TenantSummary{
				Tenant: item, LicenseState: status.State, ReadOnly: status.ReadOnly,
				IngestionEPS: numeric(overview, "ingestion_eps", "ingest_rate_eps", "eps"), Events24Hours: numeric(overview, "events_24h"),
				OpenAlerts: numeric(overview, "open_alerts"), OpenIncidents: numeric(overview, "open_incidents"),
				CollectorsUp: numeric(overview, "collectors_online"), CollectorsDown: numeric(overview, "collectors_offline"),
				Warnings: status.Warnings, CheckedAt: s.now(),
			}
		}(index, item)
	}
	wait.Wait()
	if firstErr != nil {
		return nil, total, firstErr
	}
	if err := ctx.Err(); err != nil {
		return nil, total, err
	}
	return items, total, nil
}

func (s *Service) CreateTenant(ctx context.Context, licenseTenantID string, input TenantInput) (core.Tenant, error) {
	input.ID = strings.TrimSpace(input.ID)
	input.DisplayName = strings.TrimSpace(input.DisplayName)
	if !tenant.Valid(input.ID) || input.DisplayName == "" {
		return core.Tenant{}, fmt.Errorf("%w: canonical tenant_id and display_name are required", ErrInvalidLicense)
	}
	status, err := s.Status(ctx, licenseTenantID)
	if err != nil {
		return core.Tenant{}, err
	}
	for _, limit := range status.Limits {
		if limit.Name == "tenants" && limit.Limit > 0 && limit.Used >= limit.Limit {
			return core.Tenant{}, ErrTenantLimitExceeded
		}
	}
	now := s.now()
	return s.repository.CreateTenant(ctx, core.Tenant{ID: input.ID, DisplayName: input.DisplayName, State: "ACTIVE", CreatedAt: now, UpdatedAt: now})
}

func (s *Service) SetTenantState(ctx context.Context, tenantID, state string) (core.Tenant, error) {
	state = strings.ToUpper(strings.TrimSpace(state))
	if state != "ACTIVE" && state != "SUSPENDED" {
		return core.Tenant{}, fmt.Errorf("%w: tenant state must be ACTIVE or SUSPENDED", ErrInvalidLicense)
	}
	return s.repository.SetTenantState(ctx, tenantID, state)
}

func (s *Service) verify(tenantID string, envelope core.LicenseEnvelope) (core.LicensePayload, string, error) {
	envelope.KeyID = strings.TrimSpace(envelope.KeyID)
	key, ok := s.trustedKeys[envelope.KeyID]
	if !ok {
		return core.LicensePayload{}, "", ErrUntrustedKey
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(envelope.Payload))
	if err != nil || len(payloadBytes) == 0 {
		return core.LicensePayload{}, "", fmt.Errorf("%w: malformed payload", ErrInvalidLicense)
	}
	signature, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(envelope.Signature))
	if err != nil || !ed25519.Verify(key, payloadBytes, signature) {
		return core.LicensePayload{}, "", fmt.Errorf("%w: signature verification failed", ErrInvalidLicense)
	}
	decoder := json.NewDecoder(strings.NewReader(string(payloadBytes)))
	decoder.DisallowUnknownFields()
	var payload core.LicensePayload
	if err = decoder.Decode(&payload); err != nil {
		return core.LicensePayload{}, "", fmt.Errorf("%w: decode payload: %v", ErrInvalidLicense, err)
	}
	if err = decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return core.LicensePayload{}, "", fmt.Errorf("%w: payload contains trailing data", ErrInvalidLicense)
	}
	if err = validatePayload(tenantID, payload); err != nil {
		return core.LicensePayload{}, "", err
	}
	digest := sha256.Sum256([]byte(envelope.KeyID + "." + envelope.Payload + "." + envelope.Signature))
	return payload, "sha256:" + hex.EncodeToString(digest[:]), nil
}

func validatePayload(tenantID string, payload core.LicensePayload) error {
	if payload.SchemaVersion != 1 || strings.TrimSpace(payload.LicenseID) == "" || strings.TrimSpace(payload.Customer) == "" {
		return fmt.Errorf("%w: schema_version, license_id and customer are required", ErrInvalidLicense)
	}
	if payload.IssuedAt.IsZero() || payload.NotBefore.IsZero() || payload.ExpiresAt.IsZero() || payload.GraceUntil.Before(payload.ExpiresAt) || payload.ExpiresAt.Before(payload.NotBefore) {
		return fmt.Errorf("%w: invalid validity window", ErrInvalidLicense)
	}
	allowedTenant := false
	for _, id := range payload.TenantIDs {
		if id == "*" || id == tenantID {
			allowedTenant = true
		}
		if id != "*" && !tenant.Valid(id) {
			return fmt.Errorf("%w: invalid tenant binding", ErrInvalidLicense)
		}
	}
	if !allowedTenant {
		return fmt.Errorf("%w: license is not bound to tenant", ErrInvalidLicense)
	}
	validModules := map[string]bool{}
	for _, module := range core.LicenseModules {
		validModules[module] = true
	}
	if len(payload.Modules) == 0 {
		return fmt.Errorf("%w: at least one module is required", ErrInvalidLicense)
	}
	for _, module := range payload.Modules {
		if !validModules[module] {
			return fmt.Errorf("%w: unknown module %s", ErrInvalidLicense, module)
		}
	}
	policy := strings.ToUpper(strings.TrimSpace(payload.Policy.IngestAfterExpiry))
	if policy != "ALLOW" && policy != "BLOCK" && policy != "BUFFER" {
		return fmt.Errorf("%w: ingest_after_expiry must be ALLOW, BLOCK or BUFFER", ErrInvalidLicense)
	}
	if payload.Limits.EPS < 0 || payload.Limits.EventsPerDay < 0 || payload.Limits.GBPerDay < 0 || payload.Limits.RetentionDays < 0 || payload.Limits.Assets < 0 || payload.Limits.Analysts < 0 || payload.Limits.Tenants < 0 || payload.Limits.AIRequestsPerDay < 0 || payload.Limits.PremiumConnectors < 0 {
		return fmt.Errorf("%w: limits cannot be negative", ErrInvalidLicense)
	}
	return nil
}

func licenseState(payload core.LicensePayload, now time.Time, development bool) (string, bool) {
	if development {
		return "DEVELOPMENT", false
	}
	if now.Before(payload.NotBefore) {
		return "NOT_YET_VALID", true
	}
	if !now.After(payload.ExpiresAt) {
		return "ACTIVE", false
	}
	if !now.After(payload.GraceUntil) {
		return "GRACE", false
	}
	return "EXPIRED", payload.Policy.ReadOnlyOnExpiry
}

func developmentLicense(tenantID string, now time.Time) core.LicenseRecord {
	payload := core.LicensePayload{
		SchemaVersion: 1, LicenseID: "development-unlimited", Customer: "KCSP local development", TenantIDs: []string{"*"},
		Modules: append([]string(nil), core.LicenseModules...), Features: []string{"development-profile"},
		Limits:   core.LicenseLimits{EPS: 50000, EventsPerDay: 100000000, GBPerDay: 1000, RetentionDays: 36500, Assets: 100000, Analysts: 1000, Tenants: 1000, AIRequestsPerDay: 100000, PremiumConnectors: 1000},
		Policy:   core.LicensePolicy{IngestAfterExpiry: "ALLOW", ReadOnlyOnExpiry: false},
		IssuedAt: now, NotBefore: now.Add(-time.Hour), ExpiresAt: now.Add(365 * 24 * time.Hour), GraceUntil: now.Add(395 * 24 * time.Hour),
	}
	return core.LicenseRecord{TenantID: tenantID, LicenseID: payload.LicenseID, KeyID: "development", Payload: payload, Fingerprint: "development-profile", InstalledBy: "system", Active: true, InstalledAt: now}
}

func moduleForPermission(permission string) string {
	switch {
	case strings.HasPrefix(permission, "siem."), strings.HasPrefix(permission, "detection."), strings.HasPrefix(permission, "platform.collectors."), strings.HasPrefix(permission, "platform.retention."), permission == "platform.overview.read":
		return core.LicenseModuleSIEMCore
	case strings.HasPrefix(permission, "soc."), strings.HasPrefix(permission, "reports."):
		return core.LicenseModuleSOCCore
	case strings.HasPrefix(permission, "soar."):
		return core.LicenseModuleSOAR
	case strings.HasPrefix(permission, "ai."):
		return core.LicenseModuleAISOC
	case strings.HasPrefix(permission, "ueba."):
		return core.LicenseModuleUEBA
	case strings.HasPrefix(permission, "ti."):
		return core.LicenseModuleThreatIntel
	case strings.HasPrefix(permission, "mssp."):
		return core.LicenseModuleMSSP
	case strings.HasPrefix(permission, "xdr."):
		return core.LicenseModuleXDR
	default:
		return ""
	}
}

func moduleEnabled(items []core.LicenseModuleStatus, module string) bool {
	for _, item := range items {
		if item.Module == module {
			return item.Enabled
		}
	}
	return false
}

func buildLimitStatus(limits core.LicenseLimits, overview map[string]interface{}, tenantCount int) []core.LicenseLimitStatus {
	items := []core.LicenseLimitStatus{
		limit("eps", numeric(overview, "ingestion_eps", "ingest_rate_eps", "eps"), float64(limits.EPS), "events/s"),
		limit("events_per_day", numeric(overview, "events_24h"), float64(limits.EventsPerDay), "events"),
		limit("gb_per_day", numeric(overview, "ingested_gb_24h", "gb_24h"), limits.GBPerDay, "GB"),
		limit("retention_days", numeric(overview, "retention_days"), float64(limits.RetentionDays), "days"),
		limit("assets", numeric(overview, "assets", "asset_count"), float64(limits.Assets), "assets"),
		limit("analysts", numeric(overview, "active_analysts_24h"), float64(limits.Analysts), "analysts"),
		limit("tenants", float64(tenantCount), float64(limits.Tenants), "tenants"),
		limit("ai_requests_per_day", numeric(overview, "ai_requests_24h"), float64(limits.AIRequestsPerDay), "requests"),
		limit("premium_connectors", numeric(overview, "premium_connectors"), float64(limits.PremiumConnectors), "connectors"),
	}
	return items
}

func limit(name string, used, maximum float64, unit string) core.LicenseLimitStatus {
	percent := float64(0)
	if maximum > 0 {
		percent = math.Round((used/maximum)*10000) / 100
	}
	return core.LicenseLimitStatus{Name: name, Used: used, Limit: maximum, Unit: unit, Percent: percent, Exceeded: maximum > 0 && used >= maximum}
}

func enforceQuota(permission string, limits []core.LicenseLimitStatus) error {
	checked := map[string]bool{}
	if permission == "siem.events.ingest" {
		checked["eps"] = true
		checked["events_per_day"] = true
		checked["gb_per_day"] = true
		checked["assets"] = true
	}
	if strings.HasPrefix(permission, "ai.") {
		checked["ai_requests_per_day"] = true
	}
	for _, item := range limits {
		if checked[item.Name] && item.Exceeded {
			return fmt.Errorf("%w: %s", ErrQuotaExceeded, item.Name)
		}
	}
	return nil
}

func numeric(values map[string]interface{}, keys ...string) float64 {
	for _, key := range keys {
		value, ok := values[key]
		if !ok {
			continue
		}
		switch typed := value.(type) {
		case float64:
			return typed
		case float32:
			return float64(typed)
		case int:
			return float64(typed)
		case int64:
			return float64(typed)
		case json.Number:
			parsed, _ := typed.Float64()
			return parsed
		case string:
			parsed, _ := strconv.ParseFloat(typed, 64)
			return parsed
		}
	}
	return 0
}

func sortedUnique(values []string) []string {
	seen := map[string]bool{}
	result := []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}
