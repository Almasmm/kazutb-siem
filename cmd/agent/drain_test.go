package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kcsp/platform/internal/agent"
	"github.com/kcsp/platform/internal/ingest"
)

// batchReceipt mirrors what the real gateway returns for an accepted batch.
func batchReceipt(batch ingest.RawBatchRequest) ingest.RawBatchReceipt {
	receipts := make([]ingest.Receipt, len(batch.Items))
	for i, item := range batch.Items {
		receipts[i] = ingest.Receipt{EventID: item.EventID, Status: "QUEUED"}
	}
	return ingest.RawBatchReceipt{Receipts: receipts}
}

// stubGateway accepts batch ingest and counts what it received.
func stubGateway(t *testing.T, accepted *atomic.Int64, fail *atomic.Bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/ingest/events/batch" {
			http.NotFound(w, r)
			return
		}
		if fail != nil && fail.Load() {
			http.Error(w, "gateway unavailable", http.StatusServiceUnavailable)
			return
		}
		var batch ingest.RawBatchRequest
		if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		accepted.Add(int64(len(batch.Items)))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(batchReceipt(batch))
	}))
}

func newTestForwarder(t *testing.T, serverURL string) *agent.Forwarder {
	t.Helper()
	forwarder, err := agent.NewForwarder(agent.ForwarderConfig{
		ServerURL: serverURL, TenantID: "university-kulazhanov", AccessToken: "kcsp_agent_test",
		AllowInsecureHTTP: true, Timeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return forwarder
}

func seedQueue(t *testing.T, queue *agent.DiskQueue, count int) {
	t.Helper()
	for i := 0; i < count; i++ {
		event := agent.Event{
			Format: "microsoft-windows-event-xml-v1", ContentType: "application/xml",
			EventID: fmt.Sprintf("winevent_seed_%06d", i), EventTimestamp: time.Now().UTC(),
			SourceID: "host:kaztbu", SourceAddress: "kaztbu",
			Payload: []byte("<Event><System><EventRecordID>1</EventRecordID></System></Event>"),
			Cursor:  uint64(i + 1),
		}
		if _, err := queue.Enqueue(event); err != nil {
			t.Fatal(err)
		}
	}
}

// TestDrainEmptiesBacklogInOnePass is the regression for the pilot stall: the
// old loop sent a single batch per iteration while each of five sources
// enqueued a batch in the same iteration, so delivery could never outrun
// collection and a 51k backlog only grew.
func TestDrainEmptiesBacklogInOnePass(t *testing.T) {
	var accepted atomic.Int64
	server := stubGateway(t, &accepted, nil)
	defer server.Close()

	queue, err := agent.OpenDiskQueue(t.TempDir(), 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	const backlog = 2500
	seedQueue(t, queue, backlog)

	forwarder := newTestForwarder(t, server.URL)
	defer forwarder.Close()

	delivered, err := drain(context.Background(), queue, forwarder, 100, 8<<20, 60*time.Second)
	if err != nil {
		t.Fatalf("drain failed: %v", err)
	}
	if delivered != backlog {
		t.Fatalf("drained %d of %d events in one pass", delivered, backlog)
	}
	if accepted.Load() != backlog {
		t.Fatalf("gateway accepted %d, want %d", accepted.Load(), backlog)
	}
	depth, bytes, err := queue.Depth()
	if err != nil {
		t.Fatal(err)
	}
	if depth != 0 || bytes != 0 {
		t.Fatalf("queue not empty after drain: depth=%d bytes=%d", depth, bytes)
	}
}

// TestDrainOutpacesCollection models one agent loop: five sources each enqueue
// a full batch, and delivery must still clear more than it collected.
func TestDrainOutpacesCollection(t *testing.T) {
	var accepted atomic.Int64
	server := stubGateway(t, &accepted, nil)
	defer server.Close()

	queue, err := agent.OpenDiskQueue(t.TempDir(), 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	forwarder := newTestForwarder(t, server.URL)
	defer forwarder.Close()

	const sources, batchSize = 5, 100
	// Pre-existing backlog plus what this iteration collects.
	seedQueue(t, queue, 800)
	seedQueue(t, queue, sources*batchSize)

	before, _, err := queue.Depth()
	if err != nil {
		t.Fatal(err)
	}
	delivered, err := drain(context.Background(), queue, forwarder, batchSize, 8<<20, 60*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if delivered <= sources*batchSize {
		t.Fatalf("delivery %d did not outpace one iteration of collection (%d)", delivered, sources*batchSize)
	}
	after, _, err := queue.Depth()
	if err != nil {
		t.Fatal(err)
	}
	if after >= before {
		t.Fatalf("backlog did not shrink: before=%d after=%d", before, after)
	}
	t.Logf("backlog %d -> %d, delivered %d in one iteration", before, after, delivered)
}

// TestDrainKeepsEventsWhenGatewayFails proves store-and-forward: a failing
// gateway must leave every event on disk rather than dropping it.
func TestDrainKeepsEventsWhenGatewayFails(t *testing.T) {
	var accepted atomic.Int64
	var fail atomic.Bool
	fail.Store(true)
	server := stubGateway(t, &accepted, &fail)
	defer server.Close()

	queue, err := agent.OpenDiskQueue(t.TempDir(), 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	seedQueue(t, queue, 250)
	forwarder := newTestForwarder(t, server.URL)
	defer forwarder.Close()

	delivered, err := drain(context.Background(), queue, forwarder, 100, 8<<20, 5*time.Second)
	if err == nil {
		t.Fatal("expected the failing gateway to surface an error")
	}
	if delivered != 0 {
		t.Fatalf("delivered %d events through a failing gateway", delivered)
	}
	depth, _, err := queue.Depth()
	if err != nil {
		t.Fatal(err)
	}
	if depth != 250 {
		t.Fatalf("store-and-forward lost events: depth=%d, want 250", depth)
	}

	// Once the gateway recovers, the same backlog drains.
	fail.Store(false)
	recovered, err := drain(context.Background(), queue, forwarder, 100, 8<<20, 60*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if recovered != 250 {
		t.Fatalf("recovered drain delivered %d, want 250", recovered)
	}
	final, _, err := queue.Depth()
	if err != nil {
		t.Fatal(err)
	}
	if final != 0 {
		t.Fatalf("queue still holds %d events after recovery", final)
	}
}

// TestDrainRespectsTimeBudget keeps delivery from starving source collection.
func TestDrainRespectsTimeBudget(t *testing.T) {
	var accepted atomic.Int64
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(60 * time.Millisecond)
		var batch ingest.RawBatchRequest
		_ = json.NewDecoder(r.Body).Decode(&batch)
		accepted.Add(int64(len(batch.Items)))
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(batchReceipt(batch))
	}))
	defer slow.Close()

	queue, err := agent.OpenDiskQueue(t.TempDir(), 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	seedQueue(t, queue, 3000)
	forwarder := newTestForwarder(t, slow.URL)
	defer forwarder.Close()

	start := time.Now()
	delivered, err := drain(context.Background(), queue, forwarder, 100, 8<<20, 300*time.Millisecond)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	if delivered == 0 {
		t.Fatal("budgeted drain delivered nothing")
	}
	// The budget is checked between batches, so one in-flight batch may exceed
	// it; it must not run to completion of a 3000-event backlog.
	if elapsed > 3*time.Second {
		t.Fatalf("drain ignored its time budget: %s", elapsed)
	}
	remaining, _, err := queue.Depth()
	if err != nil {
		t.Fatal(err)
	}
	if remaining == 0 {
		t.Fatal("budgeted drain should not have emptied the whole backlog")
	}
}
