package agent

import (
	"os"
	"path/filepath"
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
	info, err := os.Stat(filepath.Join(directory, "journald.checkpoint"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("checkpoint permissions = %o", info.Mode().Perm())
	}
}

func TestJournalSourceRejectsInvalidMatch(t *testing.T) {
	if _, err := NewJournalSource(t.TempDir(), []string{"not-a-match"}); err == nil {
		t.Fatal("expected invalid journald match to fail")
	}
}
