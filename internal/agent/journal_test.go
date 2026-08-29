package agent

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestParseJournalEventPreservesIdentityAndCheckpoint(t *testing.T) {
	raw := []byte(`{"__CURSOR":"s=abc;i=42","__REALTIME_TIMESTAMP":"1787446923123456","_MACHINE_ID":"AABBCC","_HOSTNAME":"linux-01","MESSAGE":"sudo authentication failure"}`)
	event, err := parseJournalEvent(raw)
	if err != nil {
		t.Fatal(err)
	}
	if event.Format != "linux-journald-json-v1" || event.Checkpoint != "s=abc;i=42" {
		t.Fatalf("unexpected journal event: %+v", event)
	}
	if event.SourceID != "host:aabbcc" || event.SourceAddress != "linux-01" || event.EventID == "" {
		t.Fatalf("host identity was not preserved: %+v", event)
	}
	if !event.EventTimestamp.Equal(time.UnixMicro(1787446923123456).UTC()) {
		t.Fatalf("event timestamp = %s", event.EventTimestamp)
	}
}

func TestJournalCheckpointIsDurable(t *testing.T) {
	directory := t.TempDir()
	source, err := NewJournalSource(directory, []string{"_SYSTEMD_UNIT=sshd.service"})
	if err != nil {
		t.Fatal(err)
	}
	if err := source.CommitEvent(Event{Checkpoint: "s=abc;i=42"}); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewJournalSource(directory, nil)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := reopened.checkpoint()
	if err != nil || checkpoint != "s=abc;i=42" {
		t.Fatalf("checkpoint = %q, err = %v", checkpoint, err)
	}
	if err := ValidatePrivateFileSecurity(filepath.Join(directory, "journald.checkpoint")); err != nil {
		t.Fatalf("checkpoint security is not private: %v", err)
	}
}

func TestJournalSourceRejectsInvalidMatch(t *testing.T) {
	if _, err := NewJournalSource(t.TempDir(), []string{"not-a-match"}); err == nil {
		t.Fatal("expected invalid journald match to fail")
	}
}

func TestJournalSourceRejectsOptionInjectionMatches(t *testing.T) {
	for _, match := range []string{
		"--output=cat",
		"lowercase=value",
		"9FIELD=value",
		"FIELD=",
		"FIELD=value\n--follow",
	} {
		if _, err := NewJournalSource(t.TempDir(), []string{match}); err == nil {
			t.Fatalf("expected journald match %q to fail", match)
		}
	}
}

func TestJournalSourceReadsJournalctlAndResumesAfterCursor(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("journalctl process contract is Linux-only")
	}
	directory := t.TempDir()
	argumentsFile := filepath.Join(directory, "arguments")
	journalctl := filepath.Join(directory, "journalctl")
	script := `#!/bin/sh
printf '%s\n' "$@" > "$KCSP_TEST_JOURNAL_ARGS"
printf '%s\n' '{"__CURSOR":"s=integration;i=7","__REALTIME_TIMESTAMP":"1787446923123456","_MACHINE_ID":"AABBCC","_HOSTNAME":"linux-01","MESSAGE":"sshd authentication failure"}'
`
	if err := os.WriteFile(journalctl, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KCSP_TEST_JOURNAL_ARGS", argumentsFile)
	t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))

	source, err := NewJournalSource(directory, []string{"_SYSTEMD_UNIT=sshd.service"})
	if err != nil {
		t.Fatal(err)
	}
	events, err := source.Read(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Checkpoint != "s=integration;i=7" {
		t.Fatalf("unexpected journald events: %+v", events)
	}
	arguments, err := os.ReadFile(argumentsFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(arguments), "--lines\n1\n") || !strings.Contains(string(arguments), "_SYSTEMD_UNIT=sshd.service\n") {
		t.Fatalf("unexpected initial journalctl arguments: %s", arguments)
	}
	if err := source.CommitEvent(events[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Read(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	arguments, err = os.ReadFile(argumentsFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(arguments), "--after-cursor\ns=integration;i=7\n") {
		t.Fatalf("journalctl did not resume after the durable cursor: %s", arguments)
	}
}
