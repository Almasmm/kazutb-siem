package agent

import (
	"fmt"
	"testing"
	"time"
)

func backlogEvent(index int) Event {
	return Event{
		Format: "microsoft-windows-event-xml-v1", ContentType: "application/xml",
		EventID: fmt.Sprintf("winevent_backlog_%06d", index), EventTimestamp: time.Unix(1756000000, 0).UTC(),
		SourceID: "host:kaztbu", SourceAddress: "kaztbu",
		Payload: []byte("<Event><System><EventRecordID>1</EventRecordID></System></Event>"),
		Cursor:  uint64(index + 1),
	}
}

// TestQueueEnqueueDoesNotDegradeWithBacklog is the regression for the pilot
// stall. Enqueue used to re-scan the whole queue directory to measure
// occupancy, making every write O(queue depth). At a 50k backlog that throttled
// the agent loop to ~25s, so delivery could never outrun collection and the
// backlog only grew. Enqueue cost must not scale with depth.
func TestQueueEnqueueDoesNotDegradeWithBacklog(t *testing.T) {
	if testing.Short() {
		t.Skip("backlog scaling test is slow under -short")
	}
	queue, err := OpenDiskQueue(t.TempDir(), 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	const sample = 200
	measure := func(offset int) time.Duration {
		start := time.Now()
		for i := 0; i < sample; i++ {
			if _, err := queue.Enqueue(backlogEvent(offset + i)); err != nil {
				t.Fatal(err)
			}
		}
		return time.Since(start)
	}

	shallow := measure(0)
	// Build a backlog an order of magnitude deeper, then measure again.
	for i := 0; i < 6000; i++ {
		if _, err := queue.Enqueue(backlogEvent(10000 + i)); err != nil {
			t.Fatal(err)
		}
	}
	deep := measure(100000)

	depth, _, err := queue.Depth()
	if err != nil {
		t.Fatal(err)
	}
	if depth != sample*2+6000 {
		t.Fatalf("depth = %d, want %d", depth, sample*2+6000)
	}
	t.Logf("enqueue %d events: shallow=%s deep(after %d backlog)=%s", sample, shallow, 6000, deep)

	// With per-write directory scans this ratio grew with depth. Allow a wide
	// margin for filesystem noise; the pre-fix behaviour was far beyond it.
	if deep > shallow*8+250*time.Millisecond {
		t.Fatalf("enqueue degraded with backlog: shallow=%s deep=%s", shallow, deep)
	}
}

// TestQueueDepthTracksEnqueueAndAck proves the cached occupancy stays exact,
// which is what the console reports as queue_depth / queue_bytes.
func TestQueueDepthTracksEnqueueAndAck(t *testing.T) {
	directory := t.TempDir()
	queue, err := OpenDiskQueue(directory, 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	if depth, bytes, err := queue.Depth(); err != nil || depth != 0 || bytes != 0 {
		t.Fatalf("empty queue: depth=%d bytes=%d err=%v", depth, bytes, err)
	}
	for i := 0; i < 25; i++ {
		if _, err := queue.Enqueue(backlogEvent(i)); err != nil {
			t.Fatal(err)
		}
	}
	depth, bytes, err := queue.Depth()
	if err != nil || depth != 25 || bytes <= 0 {
		t.Fatalf("after enqueue: depth=%d bytes=%d err=%v", depth, bytes, err)
	}

	items, err := queue.Peek(10)
	if err != nil || len(items) != 10 {
		t.Fatalf("peek: %d items, err=%v", len(items), err)
	}
	for _, item := range items {
		if err := queue.Ack(item); err != nil {
			t.Fatal(err)
		}
	}
	drained, drainedBytes, err := queue.Depth()
	if err != nil || drained != 15 {
		t.Fatalf("after ack: depth=%d err=%v", drained, err)
	}
	if drainedBytes >= bytes || drainedBytes <= 0 {
		t.Fatalf("queue bytes did not shrink: before=%d after=%d", bytes, drainedBytes)
	}

	// A freshly opened queue over the same directory must agree, proving the
	// cached totals match what is actually on disk.
	reopened, err := OpenDiskQueue(directory, 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	reopenedDepth, reopenedBytes, err := reopened.Depth()
	if err != nil || reopenedDepth != drained || reopenedBytes != drainedBytes {
		t.Fatalf("reopened queue disagrees: depth=%d/%d bytes=%d/%d err=%v",
			reopenedDepth, drained, reopenedBytes, drainedBytes, err)
	}
}

// TestQueueOldestQueuedAtReportsBacklogAge covers the backlog-age metric the
// console shows next to queue depth.
func TestQueueOldestQueuedAtReportsBacklogAge(t *testing.T) {
	queue, err := OpenDiskQueue(t.TempDir(), 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	if _, found, err := queue.OldestQueuedAt(); err != nil || found {
		t.Fatalf("empty queue must report no oldest event: found=%t err=%v", found, err)
	}
	before := time.Now().UTC()
	first, err := queue.Enqueue(backlogEvent(1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := queue.Enqueue(backlogEvent(2)); err != nil {
		t.Fatal(err)
	}
	oldest, found, err := queue.OldestQueuedAt()
	if err != nil || !found {
		t.Fatalf("expected an oldest event: found=%t err=%v", found, err)
	}
	if oldest.Before(before.Add(-time.Second)) || oldest.After(time.Now().UTC().Add(time.Second)) {
		t.Fatalf("oldest timestamp %s is outside the enqueue window", oldest)
	}
	// Acknowledging the first event moves the backlog age forward.
	if err := queue.Ack(first); err != nil {
		t.Fatal(err)
	}
	second, found, err := queue.OldestQueuedAt()
	if err != nil || !found {
		t.Fatalf("expected the remaining event: found=%t err=%v", found, err)
	}
	if second.Before(oldest) {
		t.Fatalf("backlog age went backwards: %s then %s", oldest, second)
	}
}

func TestQueueFullStillEnforced(t *testing.T) {
	queue, err := OpenDiskQueue(t.TempDir(), 2048)
	if err != nil {
		t.Fatal(err)
	}
	var lastErr error
	for i := 0; i < 100; i++ {
		if _, err := queue.Enqueue(backlogEvent(i)); err != nil {
			lastErr = err
			break
		}
	}
	if lastErr == nil {
		t.Fatal("expected the byte limit to reject an enqueue")
	}
	depth, bytes, err := queue.Depth()
	if err != nil {
		t.Fatal(err)
	}
	if bytes > 2048 {
		t.Fatalf("queue exceeded its limit: depth=%d bytes=%d", depth, bytes)
	}
}
