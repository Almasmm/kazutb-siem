package agent

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/encoding/japanese"
	"golang.org/x/text/encoding/korean"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/encoding/traditionalchinese"
	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
)

// WindowsTextEncoding names the byte encoding detected in a wevtutil stream.
type WindowsTextEncoding string

const (
	WindowsTextUTF8       WindowsTextEncoding = "utf-8"
	WindowsTextUTF8BOM    WindowsTextEncoding = "utf-8-bom"
	WindowsTextUTF16LE    WindowsTextEncoding = "utf-16le"
	WindowsTextUTF16LEBOM WindowsTextEncoding = "utf-16le-bom"
	WindowsTextUTF16BE    WindowsTextEncoding = "utf-16be"
	WindowsTextUTF16BEBOM WindowsTextEncoding = "utf-16be-bom"
	// WindowsTextANSI is the single- or multi-byte Windows code page that
	// wevtutil.exe writes when the payload leaves the ASCII range. This is the
	// encoding observed in production on ru-RU hosts (code page 1251).
	WindowsTextANSI WindowsTextEncoding = "windows-ansi"
)

// ErrUndecodableWindowsText reports a wevtutil stream that cannot be converted
// to canonical UTF-8 without losing characters. Callers must quarantine the raw
// bytes rather than forward a lossy transcription.
var ErrUndecodableWindowsText = errors.New("windows event text cannot be decoded without loss")

const (
	utf16DetectionPrefix = 512
	// replacementRune marks bytes that a code page could not represent. Its
	// presence after decoding means the chosen code page was wrong, because no
	// Windows ANSI code page encodes U+FFFD itself.
	replacementRune = '�'
)

// windowsCodePages maps Windows code page identifiers onto decoders. It covers
// every ANSI/OEM code page a Windows host can report from GetACP, so a host in
// any locale decodes its own event log correctly.
var windowsCodePages = map[int]encoding.Encoding{
	437:   charmap.CodePage437,
	850:   charmap.CodePage850,
	852:   charmap.CodePage852,
	855:   charmap.CodePage855,
	858:   charmap.CodePage858,
	860:   charmap.CodePage860,
	862:   charmap.CodePage862,
	863:   charmap.CodePage863,
	865:   charmap.CodePage865,
	866:   charmap.CodePage866,
	874:   charmap.Windows874,
	932:   japanese.ShiftJIS,
	936:   simplifiedchinese.GBK,
	949:   korean.EUCKR,
	950:   traditionalchinese.Big5,
	1250:  charmap.Windows1250,
	1251:  charmap.Windows1251,
	1252:  charmap.Windows1252,
	1253:  charmap.Windows1253,
	1254:  charmap.Windows1254,
	1255:  charmap.Windows1255,
	1256:  charmap.Windows1256,
	1257:  charmap.Windows1257,
	1258:  charmap.Windows1258,
	20866: charmap.KOI8R,
	21866: charmap.KOI8U,
	28591: charmap.ISO8859_1,
	28592: charmap.ISO8859_2,
	28593: charmap.ISO8859_3,
	28594: charmap.ISO8859_4,
	28595: charmap.ISO8859_5,
	28596: charmap.ISO8859_6,
	28597: charmap.ISO8859_7,
	28598: charmap.ISO8859_8,
	28599: charmap.ISO8859_9,
	28603: charmap.ISO8859_13,
	28605: charmap.ISO8859_15,
}

// SupportedWindowsCodePage reports whether a Windows code page can be decoded.
func SupportedWindowsCodePage(codePage int) bool {
	if codePage == 65001 || codePage == 1200 || codePage == 1201 {
		return true
	}
	_, found := windowsCodePages[codePage]
	return found
}

// DecodeWindowsEventText converts a raw wevtutil.exe byte stream into canonical
// UTF-8. wevtutil does not emit a BOM and does not honour the console code page
// when its output is redirected: it writes the host ANSI code page, so any
// non-ASCII character (Cyrillic, Kazakh, CJK) is invalid UTF-8 and makes
// encoding/xml reject the whole document. Detection order is BOM, then
// BOM-less UTF-16, then valid UTF-8, then the host ANSI code page.
//
// The conversion never substitutes or drops characters: if the bytes cannot be
// represented in the resolved code page the raw stream is rejected with
// ErrUndecodableWindowsText so the caller can quarantine it intact.
func DecodeWindowsEventText(raw []byte, ansiCodePage int) ([]byte, WindowsTextEncoding, error) {
	if len(raw) == 0 {
		return nil, WindowsTextUTF8, nil
	}
	switch {
	case hasPrefix(raw, []byte{0xEF, 0xBB, 0xBF}):
		body := raw[3:]
		if !utf8.Valid(body) {
			return nil, WindowsTextUTF8BOM, fmt.Errorf("%w: UTF-8 BOM stream holds invalid UTF-8", ErrUndecodableWindowsText)
		}
		return body, WindowsTextUTF8BOM, nil
	case hasPrefix(raw, []byte{0xFF, 0xFE}):
		decoded, err := decodeUTF16(raw[2:], unicode.LittleEndian)
		return decoded, WindowsTextUTF16LEBOM, err
	case hasPrefix(raw, []byte{0xFE, 0xFF}):
		decoded, err := decodeUTF16(raw[2:], unicode.BigEndian)
		return decoded, WindowsTextUTF16BEBOM, err
	}
	if order, ok := detectBOMlessUTF16(raw); ok {
		name := WindowsTextUTF16LE
		if order == unicode.BigEndian {
			name = WindowsTextUTF16BE
		}
		decoded, err := decodeUTF16(raw, order)
		return decoded, name, err
	}
	if utf8.Valid(raw) {
		return raw, WindowsTextUTF8, nil
	}
	decoded, err := decodeANSI(raw, ansiCodePage)
	return decoded, WindowsTextANSI, err
}

func hasPrefix(raw, prefix []byte) bool {
	if len(raw) < len(prefix) {
		return false
	}
	for i, b := range prefix {
		if raw[i] != b {
			return false
		}
	}
	return true
}

// detectBOMlessUTF16 recognises UTF-16 without a byte order mark. wevtutil XML
// is ASCII-dominated, so in UTF-16 every second byte is NUL; the side that
// carries the NULs identifies the byte order.
func detectBOMlessUTF16(raw []byte) (unicode.Endianness, bool) {
	if len(raw) < 4 {
		return unicode.LittleEndian, false
	}
	limit := len(raw)
	if limit > utf16DetectionPrefix {
		limit = utf16DetectionPrefix
	}
	limit -= limit % 2
	var evenNUL, oddNUL int
	for i := 0; i < limit; i += 2 {
		if raw[i] == 0x00 {
			evenNUL++
		}
		if raw[i+1] == 0x00 {
			oddNUL++
		}
	}
	pairs := limit / 2
	if pairs == 0 {
		return unicode.LittleEndian, false
	}
	// A real single-byte stream never carries embedded NULs, so a strong
	// one-sided majority is unambiguous.
	if oddNUL*2 > pairs && evenNUL == 0 {
		return unicode.LittleEndian, true
	}
	if evenNUL*2 > pairs && oddNUL == 0 {
		return unicode.BigEndian, true
	}
	return unicode.LittleEndian, false
}

func decodeUTF16(raw []byte, order unicode.Endianness) ([]byte, error) {
	if len(raw)%2 != 0 {
		return nil, fmt.Errorf("%w: UTF-16 stream has an odd byte length", ErrUndecodableWindowsText)
	}
	decoder := unicode.UTF16(order, unicode.IgnoreBOM).NewDecoder()
	decoded, _, err := transform.Bytes(decoder, raw)
	if err != nil {
		return nil, fmt.Errorf("%w: decode UTF-16: %v", ErrUndecodableWindowsText, err)
	}
	// An unpaired surrogate decodes to U+FFFD; treat that as corruption rather
	// than forwarding a character the host never logged.
	if containsReplacement(decoded) {
		return nil, fmt.Errorf("%w: UTF-16 stream holds unpaired surrogates", ErrUndecodableWindowsText)
	}
	return decoded, nil
}

func decodeANSI(raw []byte, codePage int) ([]byte, error) {
	if codePage == 65001 {
		return nil, fmt.Errorf("%w: stream is not valid UTF-8 but the host code page is UTF-8", ErrUndecodableWindowsText)
	}
	scheme, found := windowsCodePages[codePage]
	if !found {
		return nil, fmt.Errorf("%w: unsupported Windows code page %d", ErrUndecodableWindowsText, codePage)
	}
	decoded, _, err := transform.Bytes(scheme.NewDecoder(), raw)
	if err != nil {
		return nil, fmt.Errorf("%w: decode code page %d: %v", ErrUndecodableWindowsText, codePage, err)
	}
	if containsReplacement(decoded) {
		return nil, fmt.Errorf("%w: code page %d cannot represent every byte", ErrUndecodableWindowsText, codePage)
	}
	if !utf8.Valid(decoded) {
		return nil, fmt.Errorf("%w: code page %d produced invalid UTF-8", ErrUndecodableWindowsText, codePage)
	}
	return decoded, nil
}

func containsReplacement(decoded []byte) bool {
	return strings.ContainsRune(string(decoded), replacementRune)
}
