package collector

import (
	"bufio"
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kcsp/platform/internal/ingest"
)

func TestDetectNetworkFormats(t *testing.T) {
	t.Parallel()
	tests := []struct {
		payload string
		format  string
	}{
		{payload: `<134>1 2026-08-23T01:02:03Z fw app - - - deny`, format: ingest.FormatSyslog},
		{payload: `CEF:0|Vendor|Product|1|id|name|5|src=10.0.0.1`, format: ingest.FormatCEF},
		{payload: `<134>1 2026-08-23T01:02:03Z fw app - - - CEF:0|Vendor|Product|1|id|name|5|src=10.0.0.1`, format: ingest.FormatCEF},
		{payload: "LEEF:2.0|Vendor|Product|1|id|x09|src=10.0.0.1", format: ingest.FormatLEEF},
		{payload: `{"event_type":"alert","src_ip":"10.0.0.1"}`, format: ingest.FormatSuricataEVE},
		{payload: `{"ts":1787446923.25,"id.orig_h":"10.0.0.1"}`, format: ingest.FormatZeekJSON},
	}
	for _, test := range tests {
		format, _ := detectFormat([]byte(test.payload))
		if format != test.format {
			t.Fatalf("detectFormat(%q) = %q, want %q", test.payload, format, test.format)
		}
	}
}

func TestSyslogReceiverCapturesUDPDatagram(t *testing.T) {
	probe, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := probe.LocalAddr().String()
	_ = probe.Close()
	receiver, err := NewSyslogReceiver(SyslogConfig{UDPAddress: address, MaximumBytes: 64 << 10})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- receiver.Run(ctx) }()
	select {
	case <-receiver.Ready():
	case err := <-done:
		t.Fatalf("receiver stopped before readiness: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("receiver readiness timed out")
	}
	connection, err := net.Dial("udp", address)
	if err != nil {
		t.Fatal(err)
	}
	payload := `CEF:0|Vendor|Firewall|1|deny|Denied traffic|8|src=10.0.0.1 dst=198.51.100.1`
	if _, err := connection.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	_ = connection.Close()
	select {
	case event := <-receiver.Events():
		if event.Format != ingest.FormatCEF || event.EventID == "" || string(event.Payload) != payload || !strings.HasPrefix(event.SourceID, "ip:") {
			t.Fatalf("unexpected network event: %+v", event)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("UDP event was not received")
	}
	cancel()
	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatalf("receiver shutdown: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("receiver did not stop")
	}
}

func TestNetworkEventPreservesOriginalTimestampAndStableSourceIdentity(t *testing.T) {
	t.Parallel()
	receivedAt := time.Date(2026, 8, 23, 1, 3, 0, 0, time.UTC)
	payload := []byte(`<134>1 2026-08-23T01:02:03.123456Z fw-01 app 42 event - deny src=10.0.0.1`)
	first, err := networkEvent("ip:10.0.0.5", "10.0.0.5", payload, receivedAt)
	if err != nil {
		t.Fatal(err)
	}
	second, err := networkEvent("ip:10.0.0.5", "10.0.0.5", payload, receivedAt.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(2026, 8, 23, 1, 2, 3, 123456000, time.UTC)
	if !first.EventTimestamp.Equal(want) || first.EventID != second.EventID || first.SourceAddress != "10.0.0.5" {
		t.Fatalf("source timestamp or stable identity lost: first=%+v second=%+v", first, second)
	}
}

func TestRFC6587OctetCountedAndNewlineFrames(t *testing.T) {
	t.Parallel()
	first := `<134>1 2026-08-23T01:02:03Z fw app - - - allow`
	second := `<134>1 2026-08-23T01:02:04Z fw app - - - deny`
	stream := strconv.Itoa(len(first)) + " " + first + second + "\r\n"
	reader := bufio.NewReader(strings.NewReader(stream))
	frame, err := readSyslogFrame(reader, 64<<10)
	if err != nil || string(frame) != first {
		t.Fatalf("octet-counted frame=%q err=%v", frame, err)
	}
	frame, err = readSyslogFrame(reader, 64<<10)
	if err != nil || string(frame) != second {
		t.Fatalf("newline frame=%q err=%v", frame, err)
	}
}

func TestTLSListenerRequiresMutualTLSMaterial(t *testing.T) {
	t.Parallel()
	if _, err := NewSyslogReceiver(SyslogConfig{TLSAddress: "127.0.0.1:6514"}); err == nil {
		t.Fatal("TLS listener without identity and client CA was accepted")
	}
}
