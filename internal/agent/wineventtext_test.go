package agent

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"
	"unicode/utf8"

	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/transform"
)

const sampleEventXML = `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385f-c22a-43e0-bf4c-06f5698ffbd9}'/><EventID>1</EventID><TimeCreated SystemTime='2026-08-27T10:15:20.1234567Z'/><EventRecordID>44473</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>kaztbu</Computer></System><EventData><Data Name='User'>KAZTBU\Администратор</Data></EventData></Event>`

func encodeUTF16(t *testing.T, text string, bigEndian, bom bool) []byte {
	t.Helper()
	units := utf16.Encode([]rune(text))
	if bom {
		units = append([]uint16{0xFEFF}, units...)
	}
	buffer := new(bytes.Buffer)
	for _, unit := range units {
		var pair [2]byte
		if bigEndian {
			binary.BigEndian.PutUint16(pair[:], unit)
		} else {
			binary.LittleEndian.PutUint16(pair[:], unit)
		}
		buffer.Write(pair[:])
	}
	return buffer.Bytes()
}

func TestDecodeWindowsEventTextAcceptsEveryEncoding(t *testing.T) {
	utf8BOM := append([]byte{0xEF, 0xBB, 0xBF}, []byte(sampleEventXML)...)
	cyrillic1251, _, err := transform.Bytes(charmap.Windows1251.NewEncoder(), []byte(sampleEventXML))
	if err != nil {
		t.Fatalf("encode CP1251 fixture: %v", err)
	}

	cases := []struct {
		name     string
		raw      []byte
		codePage int
		encoding WindowsTextEncoding
	}{
		{"utf-8", []byte(sampleEventXML), 65001, WindowsTextUTF8},
		{"utf-8-bom", utf8BOM, 65001, WindowsTextUTF8BOM},
		{"utf-16le-bom", encodeUTF16(t, sampleEventXML, false, true), 1251, WindowsTextUTF16LEBOM},
		{"utf-16be-bom", encodeUTF16(t, sampleEventXML, true, true), 1251, WindowsTextUTF16BEBOM},
		{"utf-16le", encodeUTF16(t, sampleEventXML, false, false), 1251, WindowsTextUTF16LE},
		{"utf-16be", encodeUTF16(t, sampleEventXML, true, false), 1251, WindowsTextUTF16BE},
		{"windows-1251", cyrillic1251, 1251, WindowsTextANSI},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			decoded, encodingName, err := DecodeWindowsEventText(testCase.raw, testCase.codePage)
			if err != nil {
				t.Fatalf("decode %s: %v", testCase.name, err)
			}
			if encodingName != testCase.encoding {
				t.Fatalf("encoding = %q, want %q", encodingName, testCase.encoding)
			}
			if string(decoded) != sampleEventXML {
				t.Fatalf("decoded payload changed:\n got: %s\nwant: %s", decoded, sampleEventXML)
			}
			if !utf8.Valid(decoded) {
				t.Fatal("decoded output is not valid UTF-8")
			}
		})
	}
}

// TestDecodeWindowsEventTextReproducesProductionFailure locks in the exact
// defect seen on the pilot host: wevtutil emits the host ANSI code page, which
// encoding/xml rejects as invalid UTF-8.
func TestDecodeWindowsEventTextReproducesProductionFailure(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "wevtutil-cp1251.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if utf8.Valid(raw) {
		t.Fatal("fixture must be invalid UTF-8 to reproduce the reported failure")
	}
	// The pre-fix behaviour: handing these bytes straight to the XML parser.
	if _, parseErr := decodeWindowsEventHeader(splitEventXML(raw)[0]); parseErr == nil {
		t.Fatal("expected the raw ANSI stream to fail XML parsing")
	} else if !strings.Contains(parseErr.Error(), "invalid UTF-8") {
		t.Fatalf("expected an invalid UTF-8 XML error, got %v", parseErr)
	}
	decoded, encodingName, err := DecodeWindowsEventText(raw, 1251)
	if err != nil {
		t.Fatalf("decode CP1251 fixture: %v", err)
	}
	if encodingName != WindowsTextANSI {
		t.Fatalf("encoding = %q", encodingName)
	}
	if !utf8.Valid(decoded) {
		t.Fatal("decoded fixture is not valid UTF-8")
	}
	if !strings.Contains(string(decoded), "Администратор") {
		t.Fatal("Cyrillic payload was not recovered")
	}
	events := splitEventXML(decoded)
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	for _, raw := range events {
		if _, err := decodeWindowsEventHeader(raw); err != nil {
			t.Fatalf("decoded event still fails XML parsing: %v", err)
		}
	}
}

func TestDecodeWindowsEventTextRejectsLossyConversion(t *testing.T) {
	// CP1251 cannot represent Kazakh letters, so a stream that needs them must
	// be rejected rather than silently transcribed with replacement marks.
	lossy := []byte{0x3C, 0x45, 0x76, 0x65, 0x6E, 0x74, 0x20, 0x81, 0x98, 0x3E}
	if _, _, err := DecodeWindowsEventText(lossy, 1251); err == nil {
		t.Fatal("expected undecodable bytes to be rejected")
	}
	if _, _, err := DecodeWindowsEventText([]byte{0xFF, 0xD8, 0xFF}, 65001); err == nil {
		t.Fatal("expected invalid UTF-8 on a UTF-8 host to be rejected")
	}
	if _, _, err := DecodeWindowsEventText([]byte{0x80, 0x81}, 99999); err == nil {
		t.Fatal("expected an unsupported code page to be rejected")
	}
}

func TestDecodeWindowsEventTextHandlesEdgeCases(t *testing.T) {
	decoded, _, err := DecodeWindowsEventText(nil, 1251)
	if err != nil || len(decoded) != 0 {
		t.Fatalf("empty output: %q, %v", decoded, err)
	}
	truncated := encodeUTF16(t, sampleEventXML, false, true)
	if _, _, err := DecodeWindowsEventText(truncated[:len(truncated)-1], 1251); err == nil {
		t.Fatal("expected an odd-length UTF-16 stream to be rejected")
	}
	// A truncated but well-encoded stream decodes; the XML splitter simply
	// yields no complete event rather than erroring.
	partial := []byte(sampleEventXML[:120])
	decodedPartial, _, err := DecodeWindowsEventText(partial, 1251)
	if err != nil {
		t.Fatalf("truncated UTF-8: %v", err)
	}
	if len(splitEventXML(decodedPartial)) != 0 {
		t.Fatal("a truncated event must not yield a complete document")
	}
}

func TestSupportedWindowsCodePage(t *testing.T) {
	for _, codePage := range []int{65001, 1251, 1252, 866, 936, 932} {
		if !SupportedWindowsCodePage(codePage) {
			t.Fatalf("code page %d should be supported", codePage)
		}
	}
	if SupportedWindowsCodePage(99999) {
		t.Fatal("unknown code page must not report as supported")
	}
}
