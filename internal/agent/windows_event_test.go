package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// recordedReader replays canned channel content and records the queries a
// source issues, standing in for wevtapi.dll in unit tests.
type recordedReader struct {
	events   map[string][]string
	queries  []eventQuery
	failWith error
}

func newRecordedReader() *recordedReader {
	return &recordedReader{events: make(map[string][]string)}
}

func eventXML(channel, computer string, recordID uint64, second int) string {
	return fmt.Sprintf(`<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>`+
		`<Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4624</EventID>`+
		`<TimeCreated SystemTime='2026-08-27T10:15:%02d.0000000Z'/><EventRecordID>%d</EventRecordID>`+
		`<Channel>%s</Channel><Computer>%s</Computer></System></Event>`, second, recordID, channel, computer)
}

func (r *recordedReader) read(_ context.Context, query eventQuery) (eventReadResult, error) {
	r.queries = append(r.queries, query)
	if r.failWith != nil {
		return eventReadResult{}, r.failWith
	}
	records := r.events[query.Channel]
	if query.Newest {
		if len(records) == 0 {
			return eventReadResult{Encoding: WindowsTextUTF16LE}, nil
		}
		return eventReadResult{Document: []byte(records[len(records)-1]), Encoding: WindowsTextUTF16LE}, nil
	}
	limit := query.Limit
	if limit <= 0 || limit > len(records) {
		limit = len(records)
	}
	return eventReadResult{Document: []byte(strings.Join(records[:limit], "")), Encoding: WindowsTextUTF16LE}, nil
}

func newTestSource(t *testing.T, directory, channel string, mode InitialCursorMode, reader *recordedReader) *WindowsEventSource {
	t.Helper()
	source, err := NewWindowsEventSourceWithConfig(WindowsEventSourceConfig{
		StateDirectory: directory, Channel: channel, InitialCursor: mode,
		CodePage: 1251, reader: reader.read, now: func() time.Time { return time.Unix(1756000000, 0).UTC() },
	})
	if err != nil {
		t.Fatal(err)
	}
	return source
}

func TestParseInitialCursorMode(t *testing.T) {
	cases := map[string]InitialCursorMode{
		"":                 InitialCursorFromNow,
		"FROM_NOW":         InitialCursorFromNow,
		"from_now":         InitialCursorFromNow,
		"LAST_1_HOUR":      InitialCursorLast1Hour,
		"last-24-hours":    InitialCursorLast24Hours,
		"FROM_BEGINNING":   InitialCursorFromBeginning,
	}
	for input, want := range cases {
		got, err := ParseInitialCursorMode(input)
		if err != nil || got != want {
			t.Fatalf("ParseInitialCursorMode(%q) = %q, %v; want %q", input, got, err, want)
		}
	}
	if _, err := ParseInitialCursorMode("YESTERDAY"); err == nil {
		t.Fatal("expected an unknown mode to fail")
	}
}

// TestInitialCursorFromNowSkipsRetainedHistory is the regression for the pilot
// defect: a new endpoint must not replay the retained journal.
func TestInitialCursorFromNowSkipsRetainedHistory(t *testing.T) {
	reader := newRecordedReader()
	for id := uint64(44468); id <= 44472; id++ {
		reader.events["Security"] = append(reader.events["Security"], eventXML("Security", "kaztbu", id, 20))
	}
	directory := t.TempDir()
	source := newTestSource(t, directory, "Security", InitialCursorFromNow, reader)

	events, err := source.Read(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 {
		t.Fatalf("FROM_NOW must not deliver retained history, got %d events", len(events))
	}
	if source.Checkpoint() != 44472 {
		t.Fatalf("checkpoint = %d, want the latest record 44472", source.Checkpoint())
	}
	// The steady-state query must start after the resolved record, never at 0.
	steadyState := reader.queries[len(reader.queries)-1]
	if !strings.Contains(steadyState.XPath, "EventRecordID>44472") {
		t.Fatalf("steady-state query = %q, want it bounded by the resolved cursor", steadyState.XPath)
	}

	reader.events["Security"] = append(reader.events["Security"], eventXML("Security", "kaztbu", 44473, 25))
	events, err = source.Read(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Cursor != 44473 {
		t.Fatalf("expected only the new record, got %+v", events)
	}
}

func TestInitialCursorFromBeginningReadsEverything(t *testing.T) {
	reader := newRecordedReader()
	for id := uint64(1); id <= 3; id++ {
		reader.events["System"] = append(reader.events["System"], eventXML("System", "kaztbu", id, 20))
	}
	source := newTestSource(t, t.TempDir(), "System", InitialCursorFromBeginning, reader)
	events, err := source.Read(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 {
		t.Fatalf("FROM_BEGINNING should read all records, got %d", len(events))
	}
}

func TestInitialCursorTimeWindowsQueryTimediff(t *testing.T) {
	for _, testCase := range []struct {
		mode         InitialCursorMode
		milliseconds int64
	}{
		{InitialCursorLast1Hour, 3600000},
		{InitialCursorLast24Hours, 86400000},
	} {
		reader := newRecordedReader()
		reader.events["System"] = []string{eventXML("System", "kaztbu", 900, 20), eventXML("System", "kaztbu", 901, 21)}
		source := newTestSource(t, t.TempDir(), "System", testCase.mode, reader)
		if _, err := source.Read(context.Background(), 100); err != nil {
			t.Fatal(err)
		}
		want := fmt.Sprintf("timediff(@SystemTime) <= %d", testCase.milliseconds)
		if !strings.Contains(reader.queries[0].XPath, want) {
			t.Fatalf("%s query = %q, want %q", testCase.mode, reader.queries[0].XPath, want)
		}
		// The oldest record inside the window is included, so the checkpoint
		// sits one before it.
		if source.Checkpoint() != 899 {
			t.Fatalf("%s checkpoint = %d, want 899", testCase.mode, source.Checkpoint())
		}
	}
}

func TestCheckpointIsPerChannelDurableAndResumed(t *testing.T) {
	directory := t.TempDir()
	reader := newRecordedReader()
	reader.events["Security"] = []string{eventXML("Security", "kaztbu", 10, 20)}
	reader.events["System"] = []string{eventXML("System", "kaztbu", 99, 20)}

	security := newTestSource(t, directory, "Security", InitialCursorFromBeginning, reader)
	system := newTestSource(t, directory, "System", InitialCursorFromBeginning, reader)
	if security.checkpointFile == system.checkpointFile {
		t.Fatal("channels must not share a checkpoint file")
	}
	if err := security.CommitEvent(Event{Cursor: 42}); err != nil {
		t.Fatal(err)
	}
	if err := system.CommitEvent(Event{Cursor: 7}); err != nil {
		t.Fatal(err)
	}
	// Restart: a fresh source must resume from the persisted value, and the
	// channels must remain independent.
	reopened := newTestSource(t, directory, "Security", InitialCursorFromBeginning, reader)
	if got := reopened.Checkpoint(); got != 42 {
		t.Fatalf("resumed Security checkpoint = %d, want 42", got)
	}
	if got := newTestSource(t, directory, "System", InitialCursorFromBeginning, reader).Checkpoint(); got != 7 {
		t.Fatalf("resumed System checkpoint = %d, want 7", got)
	}
	// A checkpoint never moves backwards.
	if err := reopened.CommitEvent(Event{Cursor: 5}); err != nil {
		t.Fatal(err)
	}
	if got := reopened.Checkpoint(); got != 42 {
		t.Fatalf("checkpoint regressed to %d", got)
	}
}

// TestCheckpointSurvivesCrashWithoutLoss models a crash between the durable
// queue write and the next poll: the uncommitted record is delivered again
// rather than lost, and committed records are never replayed.
func TestCheckpointSurvivesCrashWithoutLoss(t *testing.T) {
	directory := t.TempDir()
	reader := newRecordedReader()
	for id := uint64(1); id <= 4; id++ {
		reader.events["System"] = append(reader.events["System"], eventXML("System", "kaztbu", id, 20))
	}
	source := newTestSource(t, directory, "System", InitialCursorFromBeginning, reader)
	events, err := source.Read(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate committing only the first two before the process dies.
	for _, event := range events[:2] {
		if err := source.CommitEvent(event); err != nil {
			t.Fatal(err)
		}
	}
	restarted := newTestSource(t, directory, "System", InitialCursorFromBeginning, reader)
	replayed, err := restarted.Read(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(replayed) != 2 || replayed[0].Cursor != 3 || replayed[1].Cursor != 4 {
		t.Fatalf("restart must replay exactly the uncommitted records, got %+v", replayed)
	}
	for _, event := range replayed {
		if err := restarted.CommitEvent(event); err != nil {
			t.Fatal(err)
		}
	}
	after, err := restarted.Read(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != 0 {
		t.Fatalf("committed records must not be replayed, got %+v", after)
	}
}

// TestSysmonChannelYieldsOneCanonicalEvent covers the duplicate-source defect:
// the same record read under two source identities must collapse to one event.
func TestSysmonChannelYieldsOneCanonicalEvent(t *testing.T) {
	reader := newRecordedReader()
	reader.events[SysmonChannel] = []string{eventXML(SysmonChannel, "kaztbu", 44473, 20)}

	legacy, err := NewSysmonSource(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	if legacy.Channel() != SysmonChannel {
		t.Fatalf("legacy constructor channel = %q", legacy.Channel())
	}
	if legacy.Name() != "windows-event:"+SysmonChannel {
		t.Fatalf("Sysmon must report one canonical identity, got %q", legacy.Name())
	}

	viaSysmon := newTestSource(t, t.TempDir(), SysmonChannel, InitialCursorFromBeginning, reader)
	viaChannel := newTestSource(t, t.TempDir(), SysmonChannel, InitialCursorFromBeginning, reader)
	first, err := viaSysmon.Read(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	second, err := viaChannel.Read(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 1 || len(second) != 1 {
		t.Fatalf("expected one event per read, got %d and %d", len(first), len(second))
	}
	if first[0].EventID != second[0].EventID {
		t.Fatalf("same record produced two identities: %q vs %q", first[0].EventID, second[0].EventID)
	}
	if !strings.HasPrefix(first[0].EventID, "sysmon_") {
		t.Fatalf("Sysmon events must keep their format prefix, got %q", first[0].EventID)
	}
	if first[0].Format != "microsoft-sysmon-xml-v1" {
		t.Fatalf("Sysmon format = %q", first[0].Format)
	}
}

// TestLegacySysmonCheckpointAdoptedOnUpgrade proves an in-place upgrade does not
// re-ingest what the 0.5.0 agent already delivered.
func TestLegacySysmonCheckpointAdoptedOnUpgrade(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, legacySysmonCheckpoint), []byte("44472"), 0o600); err != nil {
		t.Fatal(err)
	}
	reader := newRecordedReader()
	reader.events[SysmonChannel] = []string{
		eventXML(SysmonChannel, "kaztbu", 44472, 20),
		eventXML(SysmonChannel, "kaztbu", 44473, 21),
	}
	source, err := NewWindowsEventSourceWithConfig(WindowsEventSourceConfig{
		StateDirectory: directory, Channel: SysmonChannel, InitialCursor: InitialCursorFromNow,
		LegacyCheckpointFiles: []string{legacySysmonCheckpoint}, CodePage: 1251, reader: reader.read,
	})
	if err != nil {
		t.Fatal(err)
	}
	events, err := source.Read(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Cursor != 44473 {
		t.Fatalf("upgrade must resume after the legacy checkpoint, got %+v", events)
	}
}

func TestMalformedRecordIsQuarantinedWithoutBlockingChannel(t *testing.T) {
	directory := t.TempDir()
	reader := newRecordedReader()
	reader.events["System"] = []string{
		eventXML("System", "kaztbu", 1, 20),
		`<Event xmlns='urn:x'><System><EventRecordID>2</EventRecordID><Computer>kaztbu</Computer><TimeCreated SystemTime='not-a-timestamp'/><Provider Name='p'/><EventID>1</EventID></System></Event>`,
		eventXML("System", "kaztbu", 3, 22),
	}
	source := newTestSource(t, directory, "System", InitialCursorFromBeginning, reader)
	events, err := source.Read(context.Background(), 10)
	if err != nil {
		t.Fatalf("one malformed record must not fail the channel: %v", err)
	}
	if len(events) != 2 || events[0].Cursor != 1 || events[1].Cursor != 3 {
		t.Fatalf("surrounding records must still flow, got %+v", events)
	}
	if source.Quarantined() != 1 {
		t.Fatalf("quarantined = %d, want 1", source.Quarantined())
	}
	entries, err := os.ReadDir(filepath.Join(directory, "quarantine"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("expected the raw record to be preserved on disk, got %v (%v)", entries, err)
	}
}

func TestWindowsEventSourceRejectsInvalidChannel(t *testing.T) {
	if _, err := NewWindowsEventSource(t.TempDir(), "Security\nSystem"); err == nil {
		t.Fatal("expected invalid channel to fail")
	}
	if _, err := NewWindowsEventSource(t.TempDir(), ""); err == nil {
		t.Fatal("expected an empty channel to fail")
	}
}

func TestEventIdentityIsStablePerHostChannelAndRecord(t *testing.T) {
	first := windowsEventIdentity("microsoft-windows-event-xml-v1", "KAZTBU", "Security", 44473)
	same := windowsEventIdentity("microsoft-windows-event-xml-v1", "kaztbu", "security", 44473)
	otherChannel := windowsEventIdentity("microsoft-windows-event-xml-v1", "kaztbu", "System", 44473)
	otherRecord := windowsEventIdentity("microsoft-windows-event-xml-v1", "kaztbu", "Security", 44474)
	if first != same {
		t.Fatal("identity must be case-insensitive on host and channel")
	}
	if first == otherChannel || first == otherRecord {
		t.Fatal("identity must separate channels and records")
	}
}
