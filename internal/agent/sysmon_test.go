package agent

import (
	"strings"
	"testing"
)

func TestSplitEventXMLExtractsWholeRecords(t *testing.T) {
	document := []byte(eventXML("Security", "kaztbu", 41, 10) + eventXML("Security", "kaztbu", 42, 11))
	events := splitEventXML(document)
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	for index, raw := range events {
		if !strings.HasPrefix(string(raw), "<Event ") || !strings.HasSuffix(string(raw), "</Event>") {
			t.Fatalf("event %d is not a whole record: %s", index, raw)
		}
	}
	if !strings.Contains(string(events[1]), "<EventRecordID>42</EventRecordID>") {
		t.Fatalf("second record was not preserved: %s", events[1])
	}
}

func TestSplitEventXMLIgnoresIncompleteTail(t *testing.T) {
	complete := eventXML("Security", "kaztbu", 41, 10)
	document := []byte(complete + "<Event xmlns='urn:x'><System><EventRecordID>42")
	events := splitEventXML(document)
	if len(events) != 1 || string(events[0]) != complete {
		t.Fatalf("a truncated trailing record must be ignored, got %d events", len(events))
	}
	if len(splitEventXML(nil)) != 0 {
		t.Fatal("empty output must yield no events")
	}
}

// TestNewSysmonSourceIsCanonicalChannelReader documents that Sysmon is read
// through the same implementation as every other channel.
func TestNewSysmonSourceIsCanonicalChannelReader(t *testing.T) {
	source, err := NewSysmonSource(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	if source.Channel() != SysmonChannel {
		t.Fatalf("channel = %q, want %q", source.Channel(), SysmonChannel)
	}
	if source.format != "microsoft-sysmon-xml-v1" {
		t.Fatalf("format = %q", source.format)
	}
	custom, err := NewSysmonSource(t.TempDir(), "Custom-Sysmon/Operational")
	if err != nil {
		t.Fatal(err)
	}
	if custom.Channel() != "Custom-Sysmon/Operational" {
		t.Fatalf("custom channel = %q", custom.Channel())
	}
}
