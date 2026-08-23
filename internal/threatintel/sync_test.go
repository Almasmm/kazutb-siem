package threatintel

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/kcsp/platform/internal/core"
)

type feedRuntimeMemoryStore struct {
	feed       core.ThreatIntelFeed
	indicators map[string]core.ThreatIndicator
}

func (s *feedRuntimeMemoryStore) CreateThreatIntelFeed(context.Context, core.ThreatIntelFeed) (core.ThreatIntelFeed, error) {
	return core.ThreatIntelFeed{}, errors.New("unused")
}
func (s *feedRuntimeMemoryStore) GetThreatIntelFeed(context.Context, string, string) (core.ThreatIntelFeed, error) {
	return s.feed, nil
}
func (s *feedRuntimeMemoryStore) ListThreatIntelFeeds(context.Context, string) ([]core.ThreatIntelFeed, error) {
	return []core.ThreatIntelFeed{s.feed}, nil
}
func (s *feedRuntimeMemoryStore) UpdateThreatIntelFeed(context.Context, core.ThreatIntelFeed) (core.ThreatIntelFeed, error) {
	return core.ThreatIntelFeed{}, errors.New("unused")
}
func (s *feedRuntimeMemoryStore) UpsertThreatIndicator(_ context.Context, indicator core.ThreatIndicator) (core.ThreatIndicator, bool, error) {
	if s.indicators == nil {
		s.indicators = map[string]core.ThreatIndicator{}
	}
	key := string(indicator.Type) + "|" + indicator.NormalizedValue
	_, exists := s.indicators[key]
	s.indicators[key] = indicator
	return indicator, !exists, nil
}
func (s *feedRuntimeMemoryStore) GetThreatIndicator(context.Context, string, string) (core.ThreatIndicator, error) {
	return core.ThreatIndicator{}, errors.New("unused")
}
func (s *feedRuntimeMemoryStore) ListThreatIndicators(context.Context, string, core.ThreatIndicatorFilter) ([]core.ThreatIndicator, error) {
	return nil, nil
}
func (s *feedRuntimeMemoryStore) SetThreatIndicatorState(context.Context, string, string, string, int, string) (core.ThreatIndicator, error) {
	return core.ThreatIndicator{}, errors.New("unused")
}
func (s *feedRuntimeMemoryStore) ListThreatIntelMatches(context.Context, string, string, string, int) ([]core.ThreatIntelMatch, error) {
	return nil, nil
}

func TestMISPFeedRuntimeSynchronizesNormalizesAndTestsHealth(t *testing.T) {
	t.Setenv("KCSP_TI_FEED_SECRET_MISP_TEST", "misp-api-key")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "misp-api-key" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/servers/getVersion":
			_, _ = w.Write([]byte(`{"version":"2.5"}`))
		case "/attributes/restSearch":
			var request map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&request)
			if request["returnFormat"] != "json" {
				http.Error(w, "contract", http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte(`{"response":{"Attribute":[{"id":"1","uuid":"attr-1","event_id":"7","type":"ip-src","value":"203.0.113.7","timestamp":"1700000000","to_ids":true,"Tag":[{"name":"tlp:amber"}]},{"id":"2","uuid":"attr-2","event_id":"7","type":"domain","value":"evil.example","timestamp":"1700000001","to_ids":true}]}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	feed := core.ThreatIntelFeed{ID: "feed-misp", TenantID: "tenant-a", Name: "MISP", Kind: "MISP", State: core.ThreatIntelStateActive,
		SourceURL: server.URL, AuthReference: "env://KCSP_TI_FEED_SECRET_MISP_TEST", DefaultConfidence: 80, Tags: []string{"misp"}}
	store := &feedRuntimeMemoryStore{feed: feed}
	service := NewService(store)
	runtime := NewFeedRuntime(service, nil, server.Client())
	result := runtime.Sync(context.Background(), feed)
	if result.Status != core.ThreatIntelFeedSyncSucceeded || result.Imported != 2 || result.Cursor != "1700000001" || len(store.indicators) != 2 {
		t.Fatalf("unexpected MISP sync: result=%+v indicators=%+v", result, store.indicators)
	}
	health := runtime.Test(context.Background(), feed)
	if health.Status != core.ThreatIntelFeedSyncSucceeded || health.HTTPStatus != http.StatusOK {
		t.Fatalf("unexpected MISP health result: %+v", health)
	}
}

func TestOpenCTIFeedRuntimeUsesBearerGraphQLCursorAndSTIXParser(t *testing.T) {
	t.Setenv("KCSP_TI_FEED_SECRET_OPENCTI_TEST", "opencti-token")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/graphql" || r.Header.Get("Authorization") != "Bearer opencti-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var request struct {
			Query string `json:"query"`
		}
		_ = json.NewDecoder(r.Body).Decode(&request)
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(request.Query, "KcspHealth") {
			_, _ = w.Write([]byte(`{"data":{"about":{"version":"6.7"}}}`))
			return
		}
		if !strings.Contains(request.Query, "indicators") {
			http.Error(w, "contract", http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`{"data":{"indicators":{"edges":[{"cursor":"cursor-1","node":{"id":"indicator-1","standard_id":"indicator--1","pattern":"[domain-name:value = 'evil.example']","pattern_type":"stix","confidence":90,"revoked":false,"valid_from":"2026-01-01T00:00:00Z","created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-02T00:00:00Z","description":"Known C2","objectLabel":{"edges":[{"node":{"value":"c2"}}]}}}],"pageInfo":{"hasNextPage":false,"endCursor":"cursor-1"}}}}`))
	}))
	defer server.Close()
	feed := core.ThreatIntelFeed{ID: "feed-opencti", TenantID: "tenant-a", Name: "OpenCTI", Kind: "OPENCTI", State: core.ThreatIntelStateActive,
		SourceURL: server.URL, AuthReference: "env://KCSP_TI_FEED_SECRET_OPENCTI_TEST", DefaultConfidence: 70}
	store := &feedRuntimeMemoryStore{feed: feed}
	service := NewService(store)
	runtime := NewFeedRuntime(service, nil, server.Client())
	result := runtime.Sync(context.Background(), feed)
	if result.Status != core.ThreatIntelFeedSyncSucceeded || result.Imported != 1 || result.Cursor != "cursor-1" {
		t.Fatalf("unexpected OpenCTI sync: %+v", result)
	}
	for _, indicator := range store.indicators {
		if indicator.Type != core.ThreatIndicatorDomain || indicator.NormalizedValue != "evil.example" || indicator.Reputation != "MALICIOUS" {
			t.Fatalf("unexpected OpenCTI indicator: %+v", indicator)
		}
	}
	health := runtime.Test(context.Background(), feed)
	if health.Status != core.ThreatIntelFeedSyncSucceeded {
		t.Fatalf("unexpected OpenCTI health: %+v", health)
	}
}

func TestFeedRuntimeReportsMissingCredentialsWithoutCallingProvider(t *testing.T) {
	service := NewService(&feedRuntimeMemoryStore{})
	runtime := NewFeedRuntime(service, nil, nil)
	result := runtime.Sync(context.Background(), core.ThreatIntelFeed{Kind: "MISP", SourceURL: "https://misp.example.edu"})
	if result.Status != core.ThreatIntelFeedSyncCredentialsNeeded || result.ErrorClass != "CREDENTIALS_REQUIRED" {
		t.Fatalf("missing credentials were not classified: %+v", result)
	}
}

func TestFeedRuntimeRetryStopsAtContextBoundary(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	runtime := NewFeedRuntime(NewService(&feedRuntimeMemoryStore{}), nil, &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, context.DeadlineExceeded
	})})
	_, _, err := runtime.doFeedRequest(ctx, http.MethodGet, mustFeedURL(t, "https://misp.example.edu/health"), nil, "Authorization", "token")
	if err == nil {
		t.Fatal("deadline error was not returned")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }
func mustFeedURL(t *testing.T, value string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
