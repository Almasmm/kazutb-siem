package agent

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// eventQuery describes one channel read. It is expressed independently of the
// acquisition mechanism so the native Windows Event Log API and the wevtutil.exe
// fallback are interchangeable.
type eventQuery struct {
	Channel string
	// XPath filters the channel, e.g. *[System[(EventRecordID>44472)]].
	XPath string
	Limit int
	// Newest selects reverse (newest-first) ordering, used to resolve the
	// initial cursor; the steady-state read is oldest-first.
	Newest bool
}

// eventReadResult carries canonical UTF-8 event XML plus the encoding the bytes
// arrived in, which is reported in source health.
type eventReadResult struct {
	Document []byte
	Encoding WindowsTextEncoding
}

// eventReaderFunc acquires events for one query. Implementations must return
// canonical UTF-8.
type eventReaderFunc func(ctx context.Context, query eventQuery) (eventReadResult, error)

// wevtutilEventReader shells out to wevtutil.exe and decodes its output. It is
// the fallback path: wevtutil writes the host ANSI code page, which cannot
// represent every character the event log holds, so the native API is preferred.
func wevtutilEventReader(ctx context.Context, query eventQuery) (eventReadResult, error) {
	args := []string{"qe", query.Channel}
	if strings.TrimSpace(query.XPath) != "" {
		args = append(args, "/q:"+query.XPath)
	}
	args = append(args, "/f:xml")
	if query.Newest {
		args = append(args, "/rd:true")
	} else {
		args = append(args, "/rd:false")
	}
	limit := query.Limit
	if limit <= 0 {
		limit = 100
	}
	args = append(args, fmt.Sprintf("/c:%d", limit))

	output, err := execWevtutil(ctx, args...)
	if err != nil {
		return eventReadResult{}, err
	}
	decoded, encodingName, err := DecodeWindowsEventText(output, hostANSICodePage())
	if err != nil {
		return eventReadResult{}, &undecodableStreamError{Raw: output, Cause: err}
	}
	return eventReadResult{Document: decoded, Encoding: encodingName}, nil
}

// undecodableStreamError preserves the raw bytes of a stream that could not be
// converted, so the caller can quarantine them instead of discarding evidence.
type undecodableStreamError struct {
	Raw   []byte
	Cause error
}

func (e *undecodableStreamError) Error() string { return e.Cause.Error() }
func (e *undecodableStreamError) Unwrap() error { return e.Cause }

// execWevtutil runs wevtutil.exe capturing stdout separately from stderr, so a
// localised error message can never be spliced into the XML byte stream.
func execWevtutil(ctx context.Context, args ...string) ([]byte, error) {
	// #nosec G204 -- wevtutil is a fixed executable and every argument is a
	// discrete validated argv value; no shell is involved.
	command := exec.CommandContext(ctx, "wevtutil", args...)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		message := strings.TrimSpace(stderr.String())
		if decoded, _, decodeErr := DecodeWindowsEventText([]byte(message), hostANSICodePage()); decodeErr == nil {
			message = strings.TrimSpace(string(decoded))
		}
		if len(message) > 1024 {
			message = message[:1024]
		}
		return nil, fmt.Errorf("%w: %s", err, message)
	}
	return stdout.Bytes(), nil
}
