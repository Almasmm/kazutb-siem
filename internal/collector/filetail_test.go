package collector

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kcsp/platform/internal/agent"
)

func TestFileTailerPersistsCheckpointAcrossRestart(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	logPath := filepath.Join(root, "security.log")
	first := `<134>1 2026-08-23T01:02:03Z host app - first - action=deny`
	second := `<134>1 2026-08-23T01:02:04Z host app - second - action=allow`
	if err := os.WriteFile(logPath, []byte(first+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	queue, err := agent.OpenDiskQueue(filepath.Join(root, "queue"), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	config := FileTailConfig{
		Sources: []FileSource{{Path: logPath, SourceID: "file:security"}}, CheckpointDirectory: filepath.Join(root, "checkpoints"),
		PollInterval: 10 * time.Millisecond, MaximumEventBytes: 64 << 10, MaximumLinesPerPoll: 10, Queue: queue,
	}
	runTailerUntilDepth(t, config, 1)
	file, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString(second + "\n"); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	_ = file.Close()
	runTailerUntilDepth(t, config, 2)
	items, err := queue.Peek(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 || string(items[0].Event.Payload) != first || string(items[1].Event.Payload) != second {
		t.Fatalf("checkpoint replay produced loss or duplicate: %+v", items)
	}
	if items[0].Event.SourceID != "file:security" || items[0].Event.SourceAddress != logPath {
		t.Fatalf("file source identity missing: %+v", items[0].Event)
	}
}

func TestFileTailerDoesNotAdvanceCheckpointWhenQueueIsFull(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	logPath := filepath.Join(root, "audit.log")
	if err := os.WriteFile(logPath, []byte(`{"timestamp":"2026-08-23T01:02:03Z","action":"sudo","user":"student"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	queueDirectory := filepath.Join(root, "queue")
	fullQueue, err := agent.OpenDiskQueue(queueDirectory, 32)
	if err != nil {
		t.Fatal(err)
	}
	config := FileTailConfig{Sources: []FileSource{{Path: logPath, SourceID: "file:audit"}}, CheckpointDirectory: filepath.Join(root, "checkpoints"), MaximumLinesPerPoll: 10, Queue: fullQueue}
	tailer, err := NewFileTailer(config)
	if err != nil {
		t.Fatal(err)
	}
	if processed, err := tailer.pollSource(context.Background(), config.Sources[0]); processed != 0 || !errors.Is(err, agent.ErrQueueFull) {
		t.Fatalf("full queue processed=%d err=%v", processed, err)
	}
	largeQueue, err := agent.OpenDiskQueue(queueDirectory, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	config.Queue = largeQueue
	tailer, err = NewFileTailer(config)
	if err != nil {
		t.Fatal(err)
	}
	if processed, err := tailer.pollSource(context.Background(), config.Sources[0]); processed != 1 || err != nil {
		t.Fatalf("event was lost after backpressure: processed=%d err=%v", processed, err)
	}
}

func TestFileTailerRejectsUnsafeConfiguration(t *testing.T) {
	t.Parallel()
	queue, err := agent.OpenDiskQueue(t.TempDir(), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileTailer(FileTailConfig{Sources: []FileSource{{Path: "relative.log", SourceID: "file:test"}}, CheckpointDirectory: t.TempDir(), Queue: queue}); err == nil {
		t.Fatal("relative file source was accepted")
	}
	if _, err := ParseFileSourcesJSON(`[{"path":"/var/log/auth.log","source_id":"linux:auth","unknown":true}]`); err == nil {
		t.Fatal("unknown file source field was accepted")
	}
}

func runTailerUntilDepth(t *testing.T, config FileTailConfig, expected int) {
	t.Helper()
	tailer, err := NewFileTailer(config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- tailer.Run(ctx) }()
	deadline := time.After(3 * time.Second)
	for {
		depth, _, err := config.Queue.Depth()
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		if depth >= expected {
			break
		}
		select {
		case err := <-done:
			cancel()
			t.Fatalf("file tailer stopped: %v", err)
		case <-deadline:
			cancel()
			t.Fatalf("file tailer did not reach queue depth %d", expected)
		case <-time.After(10 * time.Millisecond):
		}
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("file tailer shutdown=%v", err)
	}
}
