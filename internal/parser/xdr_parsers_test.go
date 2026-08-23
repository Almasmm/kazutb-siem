package parser

import (
	"context"
	"testing"
	"time"

	"github.com/kcsp/platform/internal/ingest"
)

func TestXDRParsersNormalizeTrustedIdentity(t *testing.T) {
	t.Parallel()
	fixtures := []struct {
		name     string
		format   string
		payload  string
		category string
		parserID string
		sourceIP string
		destHost string
	}{
		{name: "windows security", format: ingest.FormatWindowsEventXML, category: "authentication", parserID: "microsoft-windows-event-xml", sourceIP: "10.20.30.40", payload: `<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4625</EventID><EventRecordID>88</EventRecordID><Channel>Security</Channel><Computer>dc-01</Computer><TimeCreated SystemTime="2026-08-23T01:02:03Z"/></System><EventData><Data Name="TargetUserName">alice</Data><Data Name="IpAddress">10.20.30.40</Data><Data Name="Status">0xC000006A</Data></EventData></Event>`},
		{name: "linux auditd", format: ingest.FormatLinuxAudit, category: "process_activity", parserID: "linux-auditd", payload: `type=SYSCALL msg=audit(1787446923.120:91) arch=c000003e syscall=59 success=yes pid=4242 ppid=1 auid=1000 uid=1000 comm="curl" exe="/usr/bin/curl" key="network-tool"`},
		{name: "journald sudo", format: ingest.FormatJournaldJSON, category: "authentication", parserID: "linux-journald-json", payload: `{"__CURSOR":"s=abc;i=42","__REALTIME_TIMESTAMP":"1787446923123456","_MACHINE_ID":"aabbcc","_HOSTNAME":"linux-01","PRIORITY":"3","SYSLOG_IDENTIFIER":"sudo","_COMM":"sudo","_PID":"4242","_UID":"1000","USER":"student","MESSAGE":"pam_unix(sudo:auth): authentication failure"}`},
		{name: "syslog firewall", format: ingest.FormatSyslog, category: "network_activity", parserID: "ietf-syslog", sourceIP: "10.1.2.3", payload: `<134>1 2026-08-23T01:02:03Z fw-01 firewall 991 deny-1 - action=deny src=10.1.2.3 dst=198.51.100.8 spt=51515 dpt=443`},
		{name: "cef", format: ingest.FormatCEF, category: "network_activity", parserID: "arcsite-cef", sourceIP: "10.1.2.3", payload: `CEF:0|Palo Alto Networks|PAN-OS|11.1|THREAT-1|Blocked C2 traffic|9|src=10.1.2.3 dst=198.51.100.8 spt=51515 dpt=443 act=blocked suser=alice`},
		{name: "leef", format: ingest.FormatLEEF, category: "network_activity", parserID: "ibm-leef", sourceIP: "10.1.2.3", payload: "LEEF:2.0|Fortinet|FortiGate|7.4|deny|x09|src=10.1.2.3\tdst=198.51.100.8\tsrcPort=51515\tdstPort=443\taction=deny\tsev=8"},
		{name: "suricata", format: ingest.FormatSuricataEVE, category: "network_activity", parserID: "oisf-suricata-eve", sourceIP: "10.1.2.3", payload: `{"timestamp":"2026-08-23T01:02:03.123456Z","flow_id":42,"event_type":"alert","src_ip":"10.1.2.3","src_port":51515,"dest_ip":"198.51.100.8","dest_port":443,"proto":"TCP","app_proto":"tls","alert":{"action":"blocked","signature":"Known C2 TLS fingerprint","category":"Command and Control","severity":1}}`},
		{name: "zeek dns", format: ingest.FormatZeekJSON, category: "dns_activity", parserID: "zeek-json", sourceIP: "10.1.2.3", destHost: "bad.example", payload: `{"ts":1787446923.25,"uid":"Cabc","id.orig_h":"10.1.2.3","id.orig_p":53000,"id.resp_h":"10.0.0.53","id.resp_p":53,"proto":"udp","query":"bad.example","qtype_name":"A","rcode_name":"NOERROR"}`},
		{name: "generic json", format: ingest.FormatGenericJSON, category: "authentication", parserID: "generic-json", sourceIP: "10.1.2.3", payload: `{"timestamp":"2026-08-23T01:02:03Z","event_type":"authentication_failure","action":"sudo failed","message":"kcsp-file-source","source_ip":"10.1.2.3","destination_ip":"10.0.0.10","username":"student","hostname":"vpn-01","severity":7}`},
	}
	registry := NewRegistry()
	for _, fixture := range fixtures {
		fixture := fixture
		t.Run(fixture.name, func(t *testing.T) {
			t.Parallel()
			receivedAt := time.Date(2026, 8, 23, 1, 3, 0, 0, time.UTC)
			event, err := registry.Parse(context.Background(), ingest.RawEnvelope{
				EventID: "trusted-event", TenantID: "tenant-a", CollectorID: "collector-a",
				SourceID: "device:firewall-01", SourceAddress: "10.0.0.1",
				Format: fixture.format, EventTimestamp: receivedAt.Add(-time.Minute), ReceivedAt: receivedAt,
				RawHash: "sha256:evidence", RawPayload: []byte(fixture.payload),
			})
			if err != nil {
				t.Fatal(err)
			}
			if event.ID != "trusted-event" || event.TenantID != "tenant-a" || event.CollectorID != "collector-a" {
				t.Fatalf("trusted envelope identity was not preserved: %+v", event)
			}
			if event.SourceID != "device:firewall-01" || event.SourceAddress != "10.0.0.1" {
				t.Fatalf("collector source identity was not preserved: %+v", event)
			}
			if event.Category != fixture.category || event.Parser.ID != fixture.parserID || event.Schema.OCSFVersion != "1.4.0" {
				t.Fatalf("unexpected normalization: category=%s parser=%+v schema=%+v", event.Category, event.Parser, event.Schema)
			}
			if fixture.sourceIP != "" && event.SrcEndpoint.IP != fixture.sourceIP {
				t.Fatalf("source IP = %q, want %q", event.SrcEndpoint.IP, fixture.sourceIP)
			}
			if fixture.destHost != "" && event.DstEndpoint.Hostname != fixture.destHost {
				t.Fatalf("destination hostname = %q, want %q", event.DstEndpoint.Hostname, fixture.destHost)
			}
			if event.Raw.Reference == "" || event.EventTime.IsZero() || event.IngestTime.IsZero() {
				t.Fatalf("evidence or timestamps missing: %+v", event)
			}
		})
	}
}

func TestRegistryPublishesXDRFormats(t *testing.T) {
	t.Parallel()
	descriptors := NewRegistry().Descriptors()
	if len(descriptors) != 11 {
		t.Fatalf("published parser descriptors = %d, want 11", len(descriptors))
	}
	for _, descriptor := range descriptors {
		if descriptor.ReleaseState != "published" || len(descriptor.Formats) == 0 {
			t.Fatalf("invalid descriptor: %+v", descriptor)
		}
	}
}
