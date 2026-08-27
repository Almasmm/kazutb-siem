package agent

import (
	"bytes"
	"errors"
)

var ErrUnsupportedSource = errors.New("event source is not supported on this operating system")

// legacySysmonCheckpoint is the checkpoint file written by agents before the
// Sysmon channel was folded into the canonical Windows Event Log source. It is
// adopted on upgrade so an existing endpoint never replays what it already sent.
const legacySysmonCheckpoint = "sysmon.checkpoint"

// NewSysmonSource returns the canonical reader for the Sysmon operational
// channel. Sysmon is an ordinary Windows Event Log channel, so it shares one
// implementation, one decoder, and one checkpoint with every other channel;
// reading it through this constructor and through the configured channel list
// therefore yields a single canonical source rather than duplicate ingestion.
func NewSysmonSource(stateDirectory, channel string) (*WindowsEventSource, error) {
	if channel == "" {
		channel = SysmonChannel
	}
	return NewWindowsEventSourceWithConfig(WindowsEventSourceConfig{
		StateDirectory:        stateDirectory,
		Channel:               channel,
		LegacyCheckpointFiles: []string{legacySysmonCheckpoint},
	})
}

// splitEventXML extracts each <Event>...</Event> document from a canonical
// UTF-8 wevtutil stream. wevtutil concatenates events without a root element,
// so the stream is not a single well-formed XML document.
func splitEventXML(document []byte) [][]byte {
	var events [][]byte
	for offset := 0; offset < len(document); {
		relativeStart := bytes.Index(document[offset:], []byte("<Event "))
		if relativeStart < 0 {
			break
		}
		start := offset + relativeStart
		relativeEnd := bytes.Index(document[start:], []byte("</Event>"))
		if relativeEnd < 0 {
			break
		}
		end := start + relativeEnd + len("</Event>")
		events = append(events, append([]byte(nil), document[start:end]...))
		offset = end
	}
	return events
}
