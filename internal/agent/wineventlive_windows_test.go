//go:build windows

package agent

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// liveChannels are readable by a non-elevated session on a normal workstation.
// Security requires elevation and is exercised separately on the pilot host.
func liveChannels() []string {
	if configured := strings.TrimSpace(os.Getenv("KCSP_AGENT_LIVE_CHANNELS")); configured != "" {
		return strings.Split(configured, ";")
	}
	return []string{"System", "Application"}
}

func requireLive(t *testing.T) {
	t.Helper()
	if strings.TrimSpace(os.Getenv("KCSP_AGENT_LIVE_EVENTLOG")) != "1" {
		t.Skip("set KCSP_AGENT_LIVE_EVENTLOG=1 to run against the real Windows Event Log")
	}
}

// TestLiveWindowsEventLogDecodesRealRecords is the runtime acceptance for the
// P0 fix: it reads the real Windows Event Log through the production path and
// asserts every record arrives as canonical UTF-8 that the XML parser accepts.
func TestLiveWindowsEventLogDecodesRealRecords(t *testing.T) {
	requireLive(t)
	for _, channel := range liveChannels() {
		t.Run(channel, func(t *testing.T) {
			source, err := NewWindowsEventSourceWithConfig(WindowsEventSourceConfig{
				StateDirectory: t.TempDir(), Channel: channel, InitialCursor: InitialCursorLast24Hours,
			})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()

			events, err := source.Read(ctx, 200)
			if err != nil {
				t.Fatalf("live read of %q failed: %v", channel, err)
			}
			t.Logf("channel=%s events=%d encoding=%s checkpoint=%d quarantined=%d",
				channel, len(events), source.Encoding(), source.Checkpoint(), source.Quarantined())
			if source.Quarantined() != 0 {
				t.Fatalf("live read quarantined %d records on %q", source.Quarantined(), channel)
			}
			if len(events) == 0 {
				t.Skipf("channel %q had no records in the last 24 hours", channel)
			}
			for _, event := range events {
				if !utf8.Valid(event.Payload) {
					t.Fatalf("record %d on %q is not valid UTF-8", event.Cursor, channel)
				}
				// The exact failure reported from the pilot host.
				if strings.Contains(string(event.Payload), "�") {
					t.Fatalf("record %d on %q contains a replacement character", event.Cursor, channel)
				}
				if _, err := decodeWindowsEventHeader(event.Payload); err != nil {
					t.Fatalf("record %d on %q failed XML decoding: %v", event.Cursor, channel, err)
				}
				if event.Cursor == 0 || event.EventID == "" || event.SourceAddress == "" {
					t.Fatalf("record on %q is missing identity: %+v", channel, event)
				}
				if event.EventTimestamp.IsZero() {
					t.Fatalf("record %d on %q has no timestamp", event.Cursor, channel)
				}
			}
		})
	}
}

// TestLiveInitialCursorFromNowDoesNotReplayHistory proves on real data that a
// new endpoint starts at the tail of the channel instead of at record 1.
func TestLiveInitialCursorFromNowDoesNotReplayHistory(t *testing.T) {
	requireLive(t)
	channel := liveChannels()[0]
	source, err := NewWindowsEventSourceWithConfig(WindowsEventSourceConfig{
		StateDirectory: t.TempDir(), Channel: channel, InitialCursor: InitialCursorFromNow,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	events, err := source.Read(ctx, 200)
	if err != nil {
		t.Fatalf("live FROM_NOW read failed: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("FROM_NOW replayed %d historical records on %q", len(events), channel)
	}
	checkpoint := source.Checkpoint()
	if checkpoint == 0 {
		t.Fatalf("FROM_NOW did not resolve a checkpoint on %q", channel)
	}
	t.Logf("channel=%s FROM_NOW checkpoint=%d (history skipped)", channel, checkpoint)
}

// TestLiveDurableCheckpointSurvivesRestart proves the checkpoint written on one
// run is honoured by the next process against the real log.
func TestLiveDurableCheckpointSurvivesRestart(t *testing.T) {
	requireLive(t)
	channel := liveChannels()[0]
	directory := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	first, err := NewWindowsEventSourceWithConfig(WindowsEventSourceConfig{
		StateDirectory: directory, Channel: channel, InitialCursor: InitialCursorLast24Hours,
	})
	if err != nil {
		t.Fatal(err)
	}
	events, err := first.Read(ctx, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) == 0 {
		t.Skipf("channel %q had no recent records", channel)
	}
	for _, event := range events {
		if err := first.CommitEvent(event); err != nil {
			t.Fatal(err)
		}
	}
	committed := first.Checkpoint()
	if committed != events[len(events)-1].Cursor {
		t.Fatalf("checkpoint = %d, want %d", committed, events[len(events)-1].Cursor)
	}
	restarted, err := NewWindowsEventSourceWithConfig(WindowsEventSourceConfig{
		StateDirectory: directory, Channel: channel, InitialCursor: InitialCursorLast24Hours,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := restarted.Checkpoint(); got != committed {
		t.Fatalf("restarted checkpoint = %d, want %d", got, committed)
	}
	replayed, err := restarted.Read(ctx, 50)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range replayed {
		if event.Cursor <= committed {
			t.Fatalf("record %d was replayed after being committed at %d", event.Cursor, committed)
		}
	}
	t.Logf("channel=%s committed=%d replayed_after_restart=%d", channel, committed, len(replayed))
}

// TestLiveQueueAndCheckpointOrdering proves the durability contract end to end
// against the real log: the event is fsynced into the local queue first, and
// only then does the checkpoint advance past it.
func TestLiveQueueAndCheckpointOrdering(t *testing.T) {
	requireLive(t)
	channel := liveChannels()[0]
	directory := t.TempDir()
	source, err := NewWindowsEventSourceWithConfig(WindowsEventSourceConfig{
		StateDirectory: directory, Channel: channel, InitialCursor: InitialCursorLast24Hours,
	})
	if err != nil {
		t.Fatal(err)
	}
	queue, err := OpenDiskQueue(directory+"\\queue", 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	events, err := source.Read(ctx, 25)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) == 0 {
		t.Skipf("channel %q had no recent records", channel)
	}
	for _, event := range events {
		before := source.Checkpoint()
		if _, err := queue.Enqueue(event); err != nil {
			t.Fatal(err)
		}
		if source.Checkpoint() != before {
			t.Fatal("checkpoint advanced before the queue write was acknowledged")
		}
		if err := source.CommitEvent(event); err != nil {
			t.Fatal(err)
		}
		if source.Checkpoint() < event.Cursor {
			t.Fatalf("checkpoint %d did not cover queued record %d", source.Checkpoint(), event.Cursor)
		}
	}
	depth, bytes, err := queue.Depth()
	if err != nil {
		t.Fatal(err)
	}
	if depth != len(events) {
		t.Fatalf("queue depth = %d, want %d", depth, len(events))
	}
	t.Logf("channel=%s queued=%d bytes=%d checkpoint=%d", channel, depth, bytes, source.Checkpoint())
}
