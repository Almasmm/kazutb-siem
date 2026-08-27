//go:build windows

package agent

import (
	"context"
	"fmt"
	"strings"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The Windows Event Log API returns event XML as UTF-16 directly from the
// service. Unlike wevtutil.exe it never transcodes through the host ANSI code
// page, so characters outside that code page survive. On a ru-RU host
// (GetACP = 1251) wevtutil replaces Kazakh letters such as ә, ө, ұ, қ, ғ, ң and
// һ with "?" before any consumer sees them; reading through this API keeps the
// payload intact, which is why it is the default acquisition path.
var (
	modwevtapi    = windows.NewLazySystemDLL("wevtapi.dll")
	procEvtQuery  = modwevtapi.NewProc("EvtQuery")
	procEvtNext   = modwevtapi.NewProc("EvtNext")
	procEvtRender = modwevtapi.NewProc("EvtRender")
	procEvtClose  = modwevtapi.NewProc("EvtClose")
)

const (
	evtQueryChannelPath      = 0x1
	evtQueryForwardDirection = 0x100
	evtQueryReverseDirection = 0x200
	evtRenderEventXML        = 1

	errorNoMoreItems         = windows.Errno(259)
	errorInsufficientBuffer  = windows.Errno(122)
	evtNextTimeoutMillisecon = 5000
)

// nativeEventReader reads a channel through wevtapi.dll and returns canonical
// UTF-8 event XML.
func nativeEventReader(ctx context.Context, query eventQuery) (eventReadResult, error) {
	if err := modwevtapi.Load(); err != nil {
		return eventReadResult{}, fmt.Errorf("load wevtapi.dll: %w", err)
	}
	channel, err := windows.UTF16PtrFromString(query.Channel)
	if err != nil {
		return eventReadResult{}, fmt.Errorf("encode channel %q: %w", query.Channel, err)
	}
	var xpath *uint16
	if strings.TrimSpace(query.XPath) != "" {
		xpath, err = windows.UTF16PtrFromString(query.XPath)
		if err != nil {
			return eventReadResult{}, fmt.Errorf("encode query for %q: %w", query.Channel, err)
		}
	}
	// EvtQueryTolerateQueryErrors is deliberately not set: it makes EvtQuery
	// succeed for a channel that does not exist, so a misconfigured channel
	// would report healthy while collecting nothing. Malformed individual
	// records are handled by per-record quarantine instead.
	flags := uintptr(evtQueryChannelPath)
	if query.Newest {
		flags |= evtQueryReverseDirection
	} else {
		flags |= evtQueryForwardDirection
	}
	handle, _, callErr := procEvtQuery.Call(0, uintptr(unsafe.Pointer(channel)), uintptr(unsafe.Pointer(xpath)), flags)
	if handle == 0 {
		return eventReadResult{}, fmt.Errorf("open Windows Event Log query for %q: %w", query.Channel, callErr)
	}
	defer procEvtClose.Call(handle)

	limit := query.Limit
	if limit <= 0 {
		limit = 100
	}
	var document []byte
	handles := make([]uintptr, 16)
	for len(documentEvents(document)) < limit {
		if err := ctx.Err(); err != nil {
			return eventReadResult{}, err
		}
		batch := len(handles)
		if remaining := limit - len(documentEvents(document)); remaining < batch {
			batch = remaining
		}
		var returned uint32
		ok, _, nextErr := procEvtNext.Call(handle, uintptr(batch), uintptr(unsafe.Pointer(&handles[0])),
			uintptr(evtNextTimeoutMillisecon), 0, uintptr(unsafe.Pointer(&returned)))
		if ok == 0 {
			if isErrno(nextErr, errorNoMoreItems) {
				break
			}
			return eventReadResult{}, fmt.Errorf("read Windows Event Log %q: %w", query.Channel, nextErr)
		}
		for i := 0; i < int(returned); i++ {
			rendered, renderErr := renderEventXML(handles[i])
			procEvtClose.Call(handles[i])
			if renderErr != nil {
				return eventReadResult{}, renderErr
			}
			document = append(document, rendered...)
		}
		if returned == 0 {
			break
		}
	}
	return eventReadResult{Document: document, Encoding: WindowsTextUTF16LE}, nil
}

// documentEvents counts complete event documents accumulated so far.
func documentEvents(document []byte) [][]byte {
	if len(document) == 0 {
		return nil
	}
	return splitEventXML(document)
}

// renderEventXML converts one event handle into canonical UTF-8 XML.
func renderEventXML(event uintptr) ([]byte, error) {
	var used, properties uint32
	ok, _, callErr := procEvtRender.Call(0, event, evtRenderEventXML, 0, 0,
		uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&properties)))
	if ok == 0 && !isErrno(callErr, errorInsufficientBuffer) {
		return nil, fmt.Errorf("size Windows event XML: %w", callErr)
	}
	if used == 0 {
		return nil, nil
	}
	buffer := make([]byte, used)
	ok, _, callErr = procEvtRender.Call(0, event, evtRenderEventXML, uintptr(used), uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&properties)))
	if ok == 0 {
		return nil, fmt.Errorf("render Windows event XML: %w", callErr)
	}
	return utf16BytesToUTF8(buffer[:used]), nil
}

// utf16BytesToUTF8 converts a UTF-16LE buffer, dropping the trailing NUL that
// EvtRender appends.
func utf16BytesToUTF8(buffer []byte) []byte {
	if len(buffer) < 2 {
		return nil
	}
	units := make([]uint16, 0, len(buffer)/2)
	for i := 0; i+1 < len(buffer); i += 2 {
		unit := uint16(buffer[i]) | uint16(buffer[i+1])<<8
		if unit == 0 {
			break
		}
		units = append(units, unit)
	}
	return []byte(string(utf16.Decode(units)))
}

func isErrno(err error, target windows.Errno) bool {
	errno, ok := err.(windows.Errno)
	return ok && errno == target
}

// defaultEventReader prefers the native API and falls back to wevtutil.exe when
// wevtapi.dll cannot be used, so acquisition still works on a restricted host.
func defaultEventReader(ctx context.Context, query eventQuery) (eventReadResult, error) {
	result, err := nativeEventReader(ctx, query)
	if err == nil {
		return result, nil
	}
	fallback, fallbackErr := wevtutilEventReader(ctx, query)
	if fallbackErr != nil {
		return eventReadResult{}, fmt.Errorf("native Windows Event Log read failed (%v); wevtutil fallback failed: %w", err, fallbackErr)
	}
	return fallback, nil
}
