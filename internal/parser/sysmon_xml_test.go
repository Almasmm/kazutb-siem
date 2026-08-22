package parser

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kcsp/platform/internal/ingest"
)

const sysmonProcessFixture = `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" />
    <EventID>1</EventID>
    <EventRecordID>4242</EventRecordID>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>DC01.kcsp.local</Computer>
    <TimeCreated SystemTime="2026-08-23T08:09:10.1234567Z" />
  </System>
  <EventData>
    <Data Name="User">KCSP\Administrator</Data>
    <Data Name="Image">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data>
    <Data Name="ProcessId">424</Data>
    <Data Name="CommandLine">powershell.exe -EncodedCommand SQBFAFgA</Data>
    <Data Name="ParentImage">C:\Windows\System32\services.exe</Data>
  </EventData>
</Event>`

func TestSysmonXMLNormalizesProcessEventAndPreservesEvidence(t *testing.T) {
	receivedAt := time.Date(2026, 8, 23, 8, 9, 12, 0, time.UTC)
	event, err := NewRegistry().Parse(context.Background(), ingest.RawEnvelope{
		EventID: "sysmon-dc01-4242", TenantID: "tenant-a", CollectorID: "agent-dc01",
		Format: ingest.FormatSysmonXML, ReceivedAt: receivedAt, RawHash: "sha256:evidence",
		RawPayload: []byte(sysmonProcessFixture),
	})
	if err != nil {
		t.Fatal(err)
	}
	wantTime := time.Date(2026, 8, 23, 8, 9, 10, 123456700, time.UTC)
	if !event.EventTime.Equal(wantTime) || !event.IngestTime.Equal(receivedAt) {
		t.Fatalf("timestamps lost: event=%s ingest=%s", event.EventTime, event.IngestTime)
	}
	if event.Category != "process_activity" || event.Schema.ClassUID != 1007 || event.Schema.OCSFVersion != "1.4.0" {
		t.Fatalf("unexpected OCSF mapping: %+v", event)
	}
	if event.Process.Name != "powershell.exe" || event.Process.PID != 424 || event.Process.ParentName != "services.exe" {
		t.Fatalf("process mapping failed: %+v", event.Process)
	}
	if event.Raw.Message != sysmonProcessFixture || event.Raw.Hash != "sha256:evidence" || event.Raw.Reference == "" {
		t.Fatalf("evidence lineage failed: %+v", event.Raw)
	}
	if event.Parser.ID != sysmonParserID || event.Parser.Version != sysmonParserVersion {
		t.Fatalf("parser version missing: %+v", event.Parser)
	}
}

func TestRegistryQuarantinesUnknownFormat(t *testing.T) {
	_, err := NewRegistry().Parse(context.Background(), ingest.RawEnvelope{Format: "unknown-vendor-v1"})
	if !errors.Is(err, ErrParse) {
		t.Fatalf("expected ErrParse, got %v", err)
	}
}
