package collector

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/kcsp/platform/internal/agent"
)

func TestAPIPollerPersistsCursorAndDeduplicatesReplay(t *testing.T) {
	root := t.TempDir()
	t.Setenv("KCSP_TEST_API_TOKEN", "test-token")
	var mu sync.Mutex
	var cursors []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(response, "unauthorized", http.StatusUnauthorized)
			return
		}
		cursor := request.URL.Query().Get("cursor")
		mu.Lock()
		cursors = append(cursors, cursor)
		mu.Unlock()
		response.Header().Set("Content-Type", "application/json")
		switch cursor {
		case "":
			_, _ = fmt.Fprint(response, `{"events":[{"id":"evt-1","action":"login"}],"next_cursor":"cursor-1","has_more":true}`)
		case "cursor-1":
			_, _ = fmt.Fprint(response, `{"events":[{"id":"evt-2","action":"deny"}],"next_cursor":"cursor-2","has_more":false}`)
		default:
			_, _ = fmt.Fprintf(response, `{"events":[],"next_cursor":%q,"has_more":false}`, cursor)
		}
	}))
	defer server.Close()
	certificate, err := x509.ParseCertificate(server.Certificate().Raw)
	if err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(root, "api-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	queue, err := agent.OpenDiskQueue(filepath.Join(root, "queue"), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	config := APIPollConfig{
		Sources:             []APISource{{SourceID: "api:identity", URL: server.URL + "/events", SecretEnv: "KCSP_TEST_API_TOKEN", CAFile: caFile}},
		CheckpointDirectory: filepath.Join(root, "checkpoints"), Queue: queue, MaximumPages: 10,
	}
	poller, err := NewAPIPoller(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := poller.pollSource(context.Background(), &poller.sources[0]); err != nil {
		t.Fatal(err)
	}
	items, err := queue.Peek(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 {
		t.Fatalf("unexpected API events: %+v", items)
	}
	byCheckpoint := map[string]agent.Event{}
	for _, item := range items {
		byCheckpoint[item.Event.Checkpoint] = item.Event
	}
	if byCheckpoint["cursor-1"].SourceID != "api:identity" || byCheckpoint["cursor-2"].SourceID != "api:identity" {
		t.Fatalf("API source identity or checkpoints are missing: %+v", items)
	}
	if items[0].Event.EventID == items[1].Event.EventID || items[0].Event.EventID == "" || items[1].Event.EventID == "" {
		t.Fatalf("API event IDs are not stable and unique: %+v", items)
	}
	if err := os.Remove(apiCheckpointPath(config.CheckpointDirectory, poller.sources[0].source)); err != nil {
		t.Fatal(err)
	}
	replayed, err := NewAPIPoller(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := replayed.pollSource(context.Background(), &replayed.sources[0]); err != nil {
		t.Fatal(err)
	}
	depth, _, err := queue.Depth()
	if err != nil || depth != 2 {
		t.Fatalf("replayed API page created duplicates: depth=%d err=%v", depth, err)
	}
	restarted, err := NewAPIPoller(config)
	if err != nil {
		t.Fatal(err)
	}
	if restarted.sources[0].cursor != "cursor-2" {
		t.Fatalf("cursor was not restored: %q", restarted.sources[0].cursor)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(cursors) != 4 || cursors[0] != "" || cursors[1] != "cursor-1" || cursors[2] != "" || cursors[3] != "cursor-1" {
		t.Fatalf("unexpected cursor sequence: %v", cursors)
	}
}

func TestAPIPollerDoesNotAdvanceCursorWhenQueueIsFull(t *testing.T) {
	root := t.TempDir()
	t.Setenv("KCSP_TEST_API_KEY", "test-key")
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("X-Vendor-Key") != "test-key" {
			http.Error(response, "unauthorized", http.StatusUnauthorized)
			return
		}
		_, _ = fmt.Fprint(response, `{"events":[{"id":"evt-1","message":"large enough to exceed the queue"}],"next_cursor":"committed","has_more":false}`)
	}))
	defer server.Close()
	caFile := writeTestAPICA(t, root, server)
	queue, err := agent.OpenDiskQueue(filepath.Join(root, "queue"), 32)
	if err != nil {
		t.Fatal(err)
	}
	config := APIPollConfig{
		Sources:             []APISource{{SourceID: "api:firewall", URL: server.URL, AuthType: "API_KEY", SecretEnv: "KCSP_TEST_API_KEY", APIKeyHeader: "X-Vendor-Key", CAFile: caFile}},
		CheckpointDirectory: filepath.Join(root, "checkpoints"), Queue: queue,
	}
	poller, err := NewAPIPoller(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := poller.pollSource(context.Background(), &poller.sources[0]); !errors.Is(err, agent.ErrQueueFull) {
		t.Fatalf("expected queue backpressure, got %v", err)
	}
	if _, found, err := loadAPICheckpoint(config.CheckpointDirectory, poller.sources[0].source); err != nil || found {
		t.Fatalf("cursor advanced while queue was full: found=%t err=%v", found, err)
	}
}

func TestAPIPollerRejectsUnsafeConfiguration(t *testing.T) {
	queue, err := agent.OpenDiskQueue(t.TempDir(), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewAPIPoller(APIPollConfig{Sources: []APISource{{SourceID: "api:test", URL: "http://example.test/events", AuthType: "MTLS"}}, CheckpointDirectory: t.TempDir(), Queue: queue}); err == nil {
		t.Fatal("plain HTTP API source was accepted")
	}
	if _, err := ParseAPISourcesJSON(`[{"source_id":"api:test","url":"https://example.test","unknown":true}]`); err == nil {
		t.Fatal("unknown API source field was accepted")
	}
}

func writeTestAPICA(t *testing.T, root string, server *httptest.Server) string {
	t.Helper()
	certificate, err := x509.ParseCertificate(server.Certificate().Raw)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "api-ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
