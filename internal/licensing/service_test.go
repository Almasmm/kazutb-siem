package licensing

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/platform/quota"
)

func TestSignedLicenseEntitlementsExpiryAndQuota(t *testing.T) {
	now := time.Date(2026, 8, 23, 3, 0, 0, 0, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	repository := newLicenseRepository(now)
	service := NewService(repository, Config{Profile: "production", TrustedKeys: map[string]ed25519.PublicKey{"airgap-2026": publicKey}, Now: func() time.Time { return now }})
	payload := validPayload(now)
	record, created, err := service.Install(context.Background(), "tenant-a", "platform-admin", InstallInput{Envelope: signLicense(t, "airgap-2026", payload, privateKey), RequestID: "install-once"})
	if err != nil || !created || record.LicenseID != payload.LicenseID {
		t.Fatalf("install failed: %#v created=%v err=%v", record, created, err)
	}
	duplicate, created, err := service.Install(context.Background(), "tenant-a", "platform-admin", InstallInput{Envelope: signLicense(t, "airgap-2026", payload, privateKey), RequestID: "install-once"})
	if err != nil || created || duplicate.LicenseID != payload.LicenseID {
		t.Fatalf("idempotent install failed: %#v created=%v err=%v", duplicate, created, err)
	}
	status, err := service.Status(context.Background(), "tenant-a")
	if err != nil || status.State != "ACTIVE" || status.ReadOnly || !moduleEnabled(status.Modules, core.LicenseModuleSIEMCore) {
		t.Fatalf("unexpected status: %#v err=%v", status, err)
	}
	if err = service.Authorize(context.Background(), "tenant-a", "siem.events.read", http.MethodGet); err != nil {
		t.Fatalf("entitled read denied: %v", err)
	}
	if err = service.ValidateRetention(context.Background(), "tenant-a", 365, 180, 90, 365); err != nil {
		t.Fatalf("licensed retention denied: %v", err)
	}
	if err = service.ValidateRetention(context.Background(), "tenant-a", 366, 180, 90, 365); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("retention quota authorization = %v", err)
	}
	if err = service.Authorize(context.Background(), "tenant-a", "soc.incidents.read", http.MethodGet); !errors.Is(err, ErrModuleNotEntitled) {
		t.Fatalf("disabled module authorization = %v", err)
	}
	repository.overview["tenant-a"] = map[string]interface{}{"events_24h": float64(payload.Limits.EventsPerDay)}
	if err = service.AuthorizeIngestBatch(context.Background(), "tenant-a", 1, 1); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("quota authorization = %v", err)
	}

	tampered := signLicense(t, "airgap-2026", payload, privateKey)
	tampered.Payload += "A"
	if _, _, err = service.Install(context.Background(), "tenant-a", "platform-admin", InstallInput{Envelope: tampered}); !errors.Is(err, ErrInvalidLicense) {
		t.Fatalf("tampered license error = %v", err)
	}
	if _, _, err = service.Install(context.Background(), "tenant-b", "platform-admin", InstallInput{Envelope: signLicense(t, "airgap-2026", payload, privateKey)}); !errors.Is(err, ErrInvalidLicense) {
		t.Fatalf("tenant binding error = %v", err)
	}
}

func TestExpiredLicenseKeepsReadsAndAppliesConfiguredIngestPolicy(t *testing.T) {
	now := time.Date(2026, 8, 23, 3, 0, 0, 0, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	repository := newLicenseRepository(now)
	payload := validPayload(now.Add(-90 * 24 * time.Hour))
	payload.ExpiresAt = now.Add(-30 * 24 * time.Hour)
	payload.GraceUntil = now.Add(-24 * time.Hour)
	payload.Policy = core.LicensePolicy{IngestAfterExpiry: "BUFFER", ReadOnlyOnExpiry: true}
	service := NewService(repository, Config{Profile: "production", TrustedKeys: map[string]ed25519.PublicKey{"offline": publicKey}, Now: func() time.Time { return now }})
	if _, _, err = service.Install(context.Background(), "tenant-a", "admin", InstallInput{Envelope: signLicense(t, "offline", payload, privateKey)}); err != nil {
		t.Fatal(err)
	}
	status, err := service.Status(context.Background(), "tenant-a")
	if err != nil || status.State != "EXPIRED" || !status.ReadOnly {
		t.Fatalf("expired status = %#v err=%v", status, err)
	}
	if err = service.Authorize(context.Background(), "tenant-a", "siem.events.read", http.MethodGet); err != nil {
		t.Fatalf("retained data read denied: %v", err)
	}
	if err = service.Authorize(context.Background(), "tenant-a", "siem.events.ingest", http.MethodPost); !errors.Is(err, ErrLicenseRestricted) {
		t.Fatalf("buffer policy did not stop direct ingest: %v", err)
	}
}

func TestDevelopmentProfileIsExplicitlyEntitled(t *testing.T) {
	now := time.Date(2026, 8, 23, 3, 0, 0, 0, time.UTC)
	repository := newLicenseRepository(now)
	service := NewService(repository, Config{Profile: "development", Now: func() time.Time { return now }})
	status, err := service.Status(context.Background(), "tenant-a")
	if err != nil || status.State != "DEVELOPMENT" || status.License == nil || status.License.KeyID != "development" {
		t.Fatalf("development status = %#v err=%v", status, err)
	}
	if err = service.Authorize(context.Background(), "tenant-a", "soar.playbooks.execute", http.MethodPost); err != nil {
		t.Fatalf("development entitlement denied: %v", err)
	}
}

func TestBatchIngestQuotaIncludesPendingEventsAndBytes(t *testing.T) {
	now := time.Date(2026, 8, 23, 3, 0, 0, 0, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	repository := newLicenseRepository(now)
	payload := validPayload(now)
	payload.Limits.EventsPerDay = 100
	payload.Limits.EPS = 10
	payload.Limits.GBPerDay = 1
	service := NewService(repository, Config{Profile: "production", TrustedKeys: map[string]ed25519.PublicKey{"offline": publicKey}, Now: func() time.Time { return now }})
	if _, _, err := service.Install(context.Background(), "tenant-a", "admin", InstallInput{Envelope: signLicense(t, "offline", payload, privateKey)}); err != nil {
		t.Fatal(err)
	}
	repository.overview["tenant-a"] = map[string]interface{}{"events_24h": float64(99), "ingestion_eps": float64(0), "ingested_gb_24h": float64(0)}
	if err := service.AuthorizeIngestBatch(context.Background(), "tenant-a", 2, 1024); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("pending events did not enforce daily quota: %v", err)
	}
	repository.overview["tenant-a"] = map[string]interface{}{"events_24h": float64(0), "ingestion_eps": float64(5), "ingested_gb_24h": float64(0)}
	if err := service.AuthorizeIngestBatch(context.Background(), "tenant-a", 6, 1024); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("pending events did not enforce EPS quota: %v", err)
	}
	repository.overview["tenant-a"] = map[string]interface{}{"events_24h": float64(0), "ingestion_eps": float64(0), "ingested_gb_24h": float64(0.75)}
	if err := service.AuthorizeIngestBatch(context.Background(), "tenant-a", 1, 300<<20); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("pending bytes did not enforce GB quota: %v", err)
	}
	if err := service.AuthorizeIngestBatch(context.Background(), "tenant-a", 1, 1<<20); err != nil {
		t.Fatalf("valid bounded batch was rejected: %v", err)
	}
}

func TestDistributedIngestQuotaBootstrapsWithoutOverviewScan(t *testing.T) {
	now := time.Date(2026, 8, 23, 3, 0, 0, 0, time.UTC)
	repository := newLicenseRepository(now)
	repository.usageEvents = 40
	repository.usageBytes = 4 << 20
	ledger := &bootstrapQuotaLedger{}
	service := NewService(repository, Config{Profile: "development", Now: func() time.Time { return now }, IngestQuota: ledger})
	if err := service.AuthorizeIngestBatch(context.Background(), "tenant-a", 5, 1024); err != nil {
		t.Fatalf("distributed quota reservation failed: %v", err)
	}
	if ledger.calls != 2 || ledger.baseline == nil || ledger.baseline.Events != 40 || ledger.baseline.Bytes != 4<<20 {
		t.Fatalf("unexpected quota bootstrap: calls=%d baseline=%#v", ledger.calls, ledger.baseline)
	}
	if repository.overviewCalls.Load() != 0 || repository.usageCalls.Load() != 1 {
		t.Fatalf("unexpected usage reads: overview=%d ingest_usage=%d", repository.overviewCalls.Load(), repository.usageCalls.Load())
	}
}

func TestTenantCatalogPaginationAndSuspension(t *testing.T) {
	now := time.Date(2026, 8, 23, 3, 0, 0, 0, time.UTC)
	repository := newLicenseRepository(now)
	for index := 0; index < 120; index++ {
		id := fmt.Sprintf("tenant-page-%03d", index)
		repository.tenants[id] = core.Tenant{ID: id, DisplayName: fmt.Sprintf("Tenant %03d", index), State: "ACTIVE", CreatedAt: now, UpdatedAt: now}
		repository.overview[id] = map[string]interface{}{"events_24h": float64(index)}
	}
	service := NewService(repository, Config{Profile: "development", Now: func() time.Time { return now }})

	first, total, err := service.Tenants(context.Background(), core.TenantFilter{Limit: 50})
	if err != nil || total != 122 || len(first) != 50 {
		t.Fatalf("first tenant page: total=%d len=%d err=%v", total, len(first), err)
	}
	second, total, err := service.Tenants(context.Background(), core.TenantFilter{Limit: 50, Offset: 50})
	if err != nil || total != 122 || len(second) != 50 {
		t.Fatalf("second tenant page: total=%d len=%d err=%v", total, len(second), err)
	}
	seen := make(map[string]bool, len(first))
	for _, item := range first {
		seen[item.Tenant.ID] = true
	}
	for _, item := range second {
		if seen[item.Tenant.ID] {
			t.Fatalf("tenant %q appears on two pages", item.Tenant.ID)
		}
	}
	matched, total, err := service.Tenants(context.Background(), core.TenantFilter{Query: "tenant-page-117", Limit: 50})
	if err != nil || total != 1 || len(matched) != 1 || matched[0].Tenant.ID != "tenant-page-117" {
		t.Fatalf("tenant search: total=%d items=%#v err=%v", total, matched, err)
	}

	if _, err = service.SetTenantState(context.Background(), "tenant-a", "SUSPENDED"); err != nil {
		t.Fatal(err)
	}
	if err = service.Authorize(context.Background(), "tenant-a", "platform.overview.read", http.MethodGet); !errors.Is(err, ErrTenantSuspended) {
		t.Fatalf("suspended tenant overview authorization = %v", err)
	}
	if err = service.Authorize(context.Background(), "tenant-a", "platform.session.read", http.MethodGet); err != nil {
		t.Fatalf("suspended tenant recovery session denied: %v", err)
	}
}

func validPayload(now time.Time) core.LicensePayload {
	return core.LicensePayload{
		SchemaVersion: 1, LicenseID: "lic-university-2026", Customer: "Kulazhanov University", TenantIDs: []string{"tenant-a"},
		Modules: []string{core.LicenseModuleSIEMCore}, Features: []string{"connector:palo-alto"},
		Limits:   core.LicenseLimits{EPS: 5000, EventsPerDay: 100000, GBPerDay: 50, RetentionDays: 365, Assets: 10000, Analysts: 50, Tenants: 2, AIRequestsPerDay: 1000, PremiumConnectors: 5},
		Policy:   core.LicensePolicy{IngestAfterExpiry: "BLOCK", ReadOnlyOnExpiry: true},
		IssuedAt: now.Add(-time.Hour), NotBefore: now.Add(-time.Hour), ExpiresAt: now.Add(365 * 24 * time.Hour), GraceUntil: now.Add(395 * 24 * time.Hour),
	}
}

func signLicense(t *testing.T, keyID string, payload core.LicensePayload, privateKey ed25519.PrivateKey) core.LicenseEnvelope {
	t.Helper()
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return core.LicenseEnvelope{KeyID: keyID, Payload: base64.RawURLEncoding.EncodeToString(encoded), Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, encoded))}
}

type licenseRepository struct {
	licenses      map[string][]core.LicenseRecord
	tenants       map[string]core.Tenant
	overview      map[string]map[string]interface{}
	usageEvents   int64
	usageBytes    int64
	usageCalls    atomic.Int64
	overviewCalls atomic.Int64
}

func newLicenseRepository(now time.Time) *licenseRepository {
	return &licenseRepository{
		licenses: map[string][]core.LicenseRecord{},
		tenants: map[string]core.Tenant{
			"tenant-a": {ID: "tenant-a", DisplayName: "Tenant A", State: "ACTIVE", CreatedAt: now, UpdatedAt: now},
			"tenant-b": {ID: "tenant-b", DisplayName: "Tenant B", State: "ACTIVE", CreatedAt: now, UpdatedAt: now},
		},
		overview: map[string]map[string]interface{}{"tenant-a": {}, "tenant-b": {}},
	}
}

func (r *licenseRepository) CurrentLicense(_ context.Context, tenantID string) (core.LicenseRecord, bool, error) {
	for _, item := range r.licenses[tenantID] {
		if item.Active {
			return item, true, nil
		}
	}
	return core.LicenseRecord{}, false, nil
}

func (r *licenseRepository) InstallLicense(_ context.Context, item core.LicenseRecord) (core.LicenseRecord, bool, error) {
	for _, existing := range r.licenses[item.TenantID] {
		if existing.RequestID != "" && existing.RequestID == item.RequestID {
			return existing, false, nil
		}
	}
	for index := range r.licenses[item.TenantID] {
		r.licenses[item.TenantID][index].Active = false
	}
	r.licenses[item.TenantID] = append(r.licenses[item.TenantID], item)
	return item, true, nil
}

func (r *licenseRepository) ListLicenses(_ context.Context, tenantID string) ([]core.LicenseRecord, error) {
	return append([]core.LicenseRecord(nil), r.licenses[tenantID]...), nil
}

func (r *licenseRepository) ListTenants(context.Context) ([]core.Tenant, error) {
	items := make([]core.Tenant, 0, len(r.tenants))
	for _, item := range r.tenants {
		items = append(items, item)
	}
	return items, nil
}

func (r *licenseRepository) GetTenant(_ context.Context, tenantID string) (core.Tenant, error) {
	return r.tenants[tenantID], nil
}

func (r *licenseRepository) CreateTenant(_ context.Context, item core.Tenant) (core.Tenant, error) {
	r.tenants[item.ID] = item
	r.overview[item.ID] = map[string]interface{}{}
	return item, nil
}

func (r *licenseRepository) SetTenantState(_ context.Context, tenantID, state string) (core.Tenant, error) {
	item := r.tenants[tenantID]
	item.State = state
	r.tenants[tenantID] = item
	return item, nil
}

func (r *licenseRepository) Overview(_ context.Context, tenantID string) (map[string]interface{}, error) {
	r.overviewCalls.Add(1)
	return r.overview[tenantID], nil
}

func (r *licenseRepository) IngestUsage(_ context.Context, _ string, _ time.Time) (int64, int64, error) {
	r.usageCalls.Add(1)
	return r.usageEvents, r.usageBytes, nil
}

type bootstrapQuotaLedger struct {
	calls    int
	baseline *quota.IngestBaseline
}

func (l *bootstrapQuotaLedger) ReserveIngest(_ context.Context, request quota.IngestReservation) (quota.IngestResult, error) {
	l.calls++
	if request.Baseline == nil {
		return quota.IngestResult{NeedsBootstrap: true, Limit: "bootstrap"}, nil
	}
	copy := *request.Baseline
	l.baseline = &copy
	return quota.IngestResult{Allowed: true, Events: copy.Events + request.Events, Bytes: copy.Bytes + request.Bytes}, nil
}
