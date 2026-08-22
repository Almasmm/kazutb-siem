package agent

import (
	"errors"
	"testing"
	"time"

	"github.com/kcsp/platform/internal/ingest"
)

func TestDiskQueuePersistsOrdersAndAcknowledgesEvents(t *testing.T) {
	directory := t.TempDir()
	queue, err := OpenDiskQueue(directory, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"event-1", "event-2"} {
		if _, err := queue.Enqueue(Event{Format: ingest.FormatSysmonXML, EventID: id, Payload: []byte("<Event />")}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Millisecond)
	}
	reopened, err := OpenDiskQueue(directory, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	items, err := reopened.Peek(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 || items[0].Event.EventID != "event-1" || items[1].Event.EventID != "event-2" {
		t.Fatalf("queue order/persistence failed: %+v", items)
	}
	if err := reopened.Ack(items[0]); err != nil {
		t.Fatal(err)
	}
	count, _, err := reopened.Depth()
	if err != nil || count != 1 {
		t.Fatalf("ack failed: count=%d err=%v", count, err)
	}
}

func TestDiskQueueAppliesBackpressureAtConfiguredLimit(t *testing.T) {
	queue, err := OpenDiskQueue(t.TempDir(), 32)
	if err != nil {
		t.Fatal(err)
	}
	_, err = queue.Enqueue(Event{Format: ingest.FormatSysmonXML, EventID: "large", Payload: make([]byte, 128)})
	if !errors.Is(err, ErrQueueFull) {
		t.Fatalf("expected ErrQueueFull, got %v", err)
	}
}
