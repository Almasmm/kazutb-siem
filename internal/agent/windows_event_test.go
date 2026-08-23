package agent

import (
	"testing"
	"time"
)

func TestParseWindowsEventsPreservesRawIdentityAndCursor(t *testing.T) {
	document := []byte(`<Events><Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4624</EventID><EventRecordID>8</EventRecordID><Channel>Security</Channel><Computer>DC01.CAMPUS.LOCAL</Computer><TimeCreated SystemTime="2026-08-23T08:09:10.123Z"/></System></Event><Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4625</EventID><EventRecordID>9</EventRecordID><Channel>Security</Channel><Computer>DC01.CAMPUS.LOCAL</Computer><TimeCreated SystemTime="2026-08-23T08:09:11.123Z"/></System></Event></Events>`)
	events, err := parseWindowsEvents(document, 8, "Security")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Cursor != 9 || events[0].Format != "microsoft-windows-event-xml-v1" {
		t.Fatalf("unexpected events: %+v", events)
	}
	if events[0].SourceID != "host:dc01.campus.local" || events[0].SourceAddress != "DC01.CAMPUS.LOCAL" {
		t.Fatalf("host identity was not preserved: %+v", events[0])
	}
	if !events[0].EventTimestamp.Equal(time.Date(2026, 8, 23, 8, 9, 11, 123000000, time.UTC)) {
		t.Fatalf("event timestamp = %s", events[0].EventTimestamp)
	}
}

func TestWindowsEventCheckpointIsPerChannelAndDurable(t *testing.T) {
	directory := t.TempDir()
	security, err := NewWindowsEventSource(directory, "Security")
	if err != nil {
		t.Fatal(err)
	}
	system, err := NewWindowsEventSource(directory, "System")
	if err != nil {
		t.Fatal(err)
	}
	if security.checkpointFile == system.checkpointFile {
		t.Fatal("different channels share a checkpoint file")
	}
	if err := security.CommitEvent(Event{Cursor: 42}); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewWindowsEventSource(directory, "Security")
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := reopened.checkpoint()
	if err != nil || checkpoint != 42 {
		t.Fatalf("checkpoint = %d, err = %v", checkpoint, err)
	}
}

func TestWindowsEventSourceRejectsInvalidChannel(t *testing.T) {
	if _, err := NewWindowsEventSource(t.TempDir(), "Security\nSystem"); err == nil {
		t.Fatal("expected invalid channel to fail")
	}
}
