package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/kcsp/platform/internal/ingest"
)

// InitialCursorMode decides where a channel starts reading the first time an
// agent sees it. A brand new endpoint must not replay months of retained
// history into the pipeline, so FROM_NOW is the default.
type InitialCursorMode string

const (
	InitialCursorFromNow       InitialCursorMode = "FROM_NOW"
	InitialCursorLast1Hour     InitialCursorMode = "LAST_1_HOUR"
	InitialCursorLast24Hours   InitialCursorMode = "LAST_24_HOURS"
	InitialCursorFromBeginning InitialCursorMode = "FROM_BEGINNING"
)

// DefaultInitialCursorMode is what a newly enrolled Windows agent uses.
const DefaultInitialCursorMode = InitialCursorFromNow

// SysmonChannel is the canonical Sysmon operational channel.
const SysmonChannel = "Microsoft-Windows-Sysmon/Operational"

// ParseInitialCursorMode accepts the documented mode names case-insensitively
// and tolerates hyphens so operators can pass last-24-hours.
func ParseInitialCursorMode(value string) (InitialCursorMode, error) {
	normalized := strings.ToUpper(strings.TrimSpace(value))
	normalized = strings.ReplaceAll(normalized, "-", "_")
	switch normalized {
	case "":
		return DefaultInitialCursorMode, nil
	case string(InitialCursorFromNow), "NOW":
		return InitialCursorFromNow, nil
	case string(InitialCursorLast1Hour), "LAST_HOUR", "1H":
		return InitialCursorLast1Hour, nil
	case string(InitialCursorLast24Hours), "LAST_DAY", "24H":
		return InitialCursorLast24Hours, nil
	case string(InitialCursorFromBeginning), "BEGINNING", "ALL":
		return InitialCursorFromBeginning, nil
	default:
		return "", fmt.Errorf("unsupported initial cursor mode %q", value)
	}
}

// lookbehind reports the backfill window for the time-bounded modes.
func (m InitialCursorMode) lookbehind() (time.Duration, bool) {
	switch m {
	case InitialCursorLast1Hour:
		return time.Hour, true
	case InitialCursorLast24Hours:
		return 24 * time.Hour, true
	default:
		return 0, false
	}
}

// WindowsEventSourceConfig configures one channel reader. One instance owns one
// channel and one durable checkpoint; channels never share a checkpoint.
type WindowsEventSourceConfig struct {
	StateDirectory string
	Channel        string
	InitialCursor  InitialCursorMode
	// Format overrides the ingest format. Sysmon keeps its dedicated format so
	// the server-side parser continues to recognise it.
	Format string
	// DisplayName overrides the reported source name. Used to keep the legacy
	// "sysmon" identity reporting under its canonical channel source.
	DisplayName string
	// LegacyCheckpointFiles are checkpoints written by earlier agent versions.
	// The highest value found is adopted so an upgrade never replays events.
	LegacyCheckpointFiles []string
	// CodePage overrides the detected host ANSI code page. Zero means detect.
	CodePage int

	reader eventReaderFunc
	now    func() time.Time
}

type WindowsEventSource struct {
	channel        string
	displayName    string
	format         string
	initialCursor  InitialCursorMode
	checkpointFile string
	legacyFiles    []string
	quarantineDir  string
	codePage       int
	reader         eventReaderFunc
	now            func() time.Time

	quarantined uint64
	lastEncoding WindowsTextEncoding
}

// NewWindowsEventSource builds a channel reader with default cursor semantics.
func NewWindowsEventSource(stateDirectory, channel string) (*WindowsEventSource, error) {
	return NewWindowsEventSourceWithConfig(WindowsEventSourceConfig{StateDirectory: stateDirectory, Channel: channel})
}

func NewWindowsEventSourceWithConfig(config WindowsEventSourceConfig) (*WindowsEventSource, error) {
	stateDirectory := strings.TrimSpace(config.StateDirectory)
	channel := strings.TrimSpace(config.Channel)
	if stateDirectory == "" {
		return nil, errors.New("agent state directory is required")
	}
	if channel == "" || len(channel) > 256 || strings.ContainsAny(channel, "\r\n") {
		return nil, errors.New("valid Windows Event Log channel is required")
	}
	if err := os.MkdirAll(stateDirectory, 0o700); err != nil {
		return nil, fmt.Errorf("create agent state directory: %w", err)
	}
	mode := config.InitialCursor
	if strings.TrimSpace(string(mode)) == "" {
		mode = DefaultInitialCursorMode
	}
	if _, err := ParseInitialCursorMode(string(mode)); err != nil {
		return nil, err
	}
	format := strings.TrimSpace(config.Format)
	if format == "" {
		format = ingest.FormatWindowsEventXML
		if strings.EqualFold(channel, SysmonChannel) {
			format = ingest.FormatSysmonXML
		}
	}
	displayName := strings.TrimSpace(config.DisplayName)
	if displayName == "" {
		displayName = "windows-event:" + channel
	}
	codePage := config.CodePage
	if codePage == 0 {
		codePage = hostANSICodePage()
	}
	reader := config.reader
	if reader == nil {
		reader = defaultEventReader
	}
	nowFunc := config.now
	if nowFunc == nil {
		nowFunc = time.Now
	}
	identity := sha256.Sum256([]byte(strings.ToLower(channel)))
	legacy := make([]string, 0, len(config.LegacyCheckpointFiles))
	for _, name := range config.LegacyCheckpointFiles {
		if strings.TrimSpace(name) == "" {
			continue
		}
		legacy = append(legacy, filepath.Join(stateDirectory, name))
	}
	return &WindowsEventSource{
		channel:        channel,
		displayName:    displayName,
		format:         format,
		initialCursor:  mode,
		checkpointFile: filepath.Join(stateDirectory, "windows-event-"+hex.EncodeToString(identity[:8])+".checkpoint"),
		legacyFiles:    legacy,
		quarantineDir:  filepath.Join(stateDirectory, "quarantine"),
		codePage:       codePage,
		reader:         reader,
		now:            nowFunc,
	}, nil
}

func (s *WindowsEventSource) Name() string { return s.displayName }

// Channel reports the canonical Windows channel this source owns.
func (s *WindowsEventSource) Channel() string { return s.channel }

// Checkpoint exposes the durable record ID for health reporting.
func (s *WindowsEventSource) Checkpoint() uint64 {
	value, err := s.checkpoint()
	if err != nil {
		return 0
	}
	return value
}

// Quarantined counts events this source could not decode and set aside.
func (s *WindowsEventSource) Quarantined() uint64 { return s.quarantined }

// Encoding reports the encoding detected on the last successful read.
func (s *WindowsEventSource) Encoding() WindowsTextEncoding { return s.lastEncoding }

func (s *WindowsEventSource) Read(ctx context.Context, limit int) ([]Event, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	checkpoint, err := s.ensureCheckpoint(ctx)
	if err != nil {
		return nil, err
	}
	result, err := s.read(ctx, eventQuery{
		Channel: s.channel,
		XPath:   fmt.Sprintf("*[System[(EventRecordID>%d)]]", checkpoint),
		Limit:   limit,
	})
	if err != nil {
		return nil, fmt.Errorf("read Windows Event Log channel %q: %w", s.channel, err)
	}
	s.lastEncoding = result.Encoding
	events, quarantined := s.parseDocument(result.Document, checkpoint)
	s.quarantined += uint64(len(quarantined))
	for _, record := range quarantined {
		s.writeQuarantine(record)
	}
	return events, nil
}

// ensureCheckpoint resolves and durably stores the initial cursor the first
// time a channel is seen, so a restart never re-derives a different origin.
func (s *WindowsEventSource) ensureCheckpoint(ctx context.Context) (uint64, error) {
	current, err := s.checkpoint()
	if err != nil {
		return 0, err
	}
	if current > 0 {
		return current, nil
	}
	if s.checkpointExists() {
		return current, nil
	}
	if adopted, found, err := s.adoptLegacyCheckpoint(); err != nil {
		return 0, err
	} else if found {
		if err := s.writeCheckpoint(adopted); err != nil {
			return 0, err
		}
		return adopted, nil
	}
	resolved, err := s.resolveInitialCursor(ctx)
	if err != nil {
		return 0, err
	}
	if err := s.writeCheckpoint(resolved); err != nil {
		return 0, err
	}
	return resolved, nil
}

func (s *WindowsEventSource) resolveInitialCursor(ctx context.Context) (uint64, error) {
	switch s.initialCursor {
	case InitialCursorFromBeginning:
		return 0, nil
	case InitialCursorLast1Hour, InitialCursorLast24Hours:
		window, _ := s.initialCursor.lookbehind()
		milliseconds := window.Milliseconds()
		xpath := fmt.Sprintf("*[System[TimeCreated[timediff(@SystemTime) <= %d]]]", milliseconds)
		// Oldest-first ordering makes the first record in the window the
		// backfill origin; start one before it so that record is included.
		record, found, err := s.firstRecordID(ctx, xpath, false)
		if err != nil {
			return 0, err
		}
		if found {
			if record == 0 {
				return 0, nil
			}
			return record - 1, nil
		}
		// No events in the window: fall through to the newest record so the
		// agent still refuses to replay retained history.
		return s.latestRecordID(ctx)
	default:
		return s.latestRecordID(ctx)
	}
}

// latestRecordID returns the newest record currently in the channel.
func (s *WindowsEventSource) latestRecordID(ctx context.Context) (uint64, error) {
	record, found, err := s.firstRecordID(ctx, "*[System[(EventRecordID>0)]]", true)
	if err != nil {
		return 0, err
	}
	if !found {
		return 0, nil
	}
	return record, nil
}

func (s *WindowsEventSource) firstRecordID(ctx context.Context, xpath string, newest bool) (uint64, bool, error) {
	result, err := s.read(ctx, eventQuery{Channel: s.channel, XPath: xpath, Limit: 1, Newest: newest})
	if err != nil {
		return 0, false, fmt.Errorf("resolve initial cursor for %q: %w", s.channel, err)
	}
	for _, raw := range splitEventXML(result.Document) {
		header, err := decodeWindowsEventHeader(raw)
		if err != nil {
			continue
		}
		if header.System.EventRecordID > 0 {
			return header.System.EventRecordID, true, nil
		}
	}
	return 0, false, nil
}

// read performs one acquisition and quarantines the raw bytes of any stream
// that could not be converted to canonical UTF-8.
func (s *WindowsEventSource) read(ctx context.Context, query eventQuery) (eventReadResult, error) {
	result, err := s.reader(ctx, query)
	if err != nil {
		var undecodable *undecodableStreamError
		if errors.As(err, &undecodable) {
			s.quarantineStream(undecodable.Raw, undecodable.Cause)
		}
		return eventReadResult{}, err
	}
	return result, nil
}

func (s *WindowsEventSource) CommitEvent(event Event) error {
	if event.Cursor == 0 {
		return errors.New("cannot commit empty Windows Event Log cursor")
	}
	current, err := s.checkpoint()
	if err != nil {
		return err
	}
	if event.Cursor <= current {
		return nil
	}
	return s.writeCheckpoint(event.Cursor)
}

func (s *WindowsEventSource) checkpointExists() bool {
	_, err := os.Stat(s.checkpointFile)
	return err == nil
}

func (s *WindowsEventSource) adoptLegacyCheckpoint() (uint64, bool, error) {
	var highest uint64
	found := false
	for _, name := range s.legacyFiles {
		value, err := readCheckpointFile(name)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return 0, false, err
		}
		found = true
		if value > highest {
			highest = value
		}
	}
	return highest, found, nil
}

func (s *WindowsEventSource) checkpoint() (uint64, error) {
	value, err := readCheckpointFile(s.checkpointFile)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return value, nil
}

func (s *WindowsEventSource) writeCheckpoint(cursor uint64) error {
	return writeCheckpointFile(s.checkpointFile, ".windows-event-checkpoint-*", cursor)
}

// parseDocument converts canonical UTF-8 wevtutil output into events. A single
// malformed record is quarantined and the remaining records still flow, so one
// bad event can never wedge a channel.
func (s *WindowsEventSource) parseDocument(document []byte, after uint64) ([]Event, []quarantineRecord) {
	rawEvents := splitEventXML(document)
	events := make([]Event, 0, len(rawEvents))
	var quarantined []quarantineRecord
	for _, raw := range rawEvents {
		event, err := s.buildEvent(raw, after)
		if err != nil {
			if errors.Is(err, errSkipRecord) {
				continue
			}
			quarantined = append(quarantined, quarantineRecord{
				Channel: s.channel,
				Reason:  err.Error(),
				Raw:     raw,
			})
			continue
		}
		events = append(events, event)
	}
	return events, quarantined
}

var errSkipRecord = errors.New("record already delivered")

type windowsEventHeader struct {
	System struct {
		Provider struct {
			Name string `xml:"Name,attr"`
		} `xml:"Provider"`
		EventID       string `xml:"EventID"`
		EventRecordID uint64 `xml:"EventRecordID"`
		Channel       string `xml:"Channel"`
		Computer      string `xml:"Computer"`
		TimeCreated   struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
	} `xml:"System"`
}

func decodeWindowsEventHeader(raw []byte) (windowsEventHeader, error) {
	var header windowsEventHeader
	if err := xml.Unmarshal(raw, &header); err != nil {
		return windowsEventHeader{}, fmt.Errorf("decode Windows Event Log header: %w", err)
	}
	return header, nil
}

func (s *WindowsEventSource) buildEvent(raw []byte, after uint64) (Event, error) {
	header, err := decodeWindowsEventHeader(raw)
	if err != nil {
		return Event{}, err
	}
	if header.System.EventRecordID == 0 {
		return Event{}, errors.New("decode Windows Event Log header: event record ID is required")
	}
	if header.System.EventRecordID <= after {
		return Event{}, errSkipRecord
	}
	computer := strings.TrimSpace(header.System.Computer)
	provider := strings.TrimSpace(header.System.Provider.Name)
	eventCode := strings.TrimSpace(header.System.EventID)
	if computer == "" || provider == "" || eventCode == "" {
		return Event{}, errors.New("decode Windows Event Log header: computer, provider, and event ID are required")
	}
	eventTime, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(header.System.TimeCreated.SystemTime))
	if err != nil {
		return Event{}, fmt.Errorf("parse Windows Event Log timestamp: %w", err)
	}
	channel := strings.TrimSpace(header.System.Channel)
	if channel == "" {
		channel = s.channel
	}
	return Event{
		Format:         s.format,
		ContentType:    "application/xml",
		EventID:        windowsEventIdentity(s.format, computer, channel, header.System.EventRecordID),
		EventTimestamp: eventTime.UTC(),
		SourceID:       "host:" + strings.ToLower(computer),
		SourceAddress:  computer,
		Payload:        append([]byte(nil), raw...),
		Cursor:         header.System.EventRecordID,
	}, nil
}

// windowsEventIdentity derives one stable ID per (host, channel, record). The
// channel is part of the digest so a channel read through two configured
// sources still collapses onto a single canonical event.
func windowsEventIdentity(format, computer, channel string, recordID uint64) string {
	digest := sha256.Sum256([]byte(strings.ToLower(computer) + "|" + strings.ToLower(channel) + "|" + strconv.FormatUint(recordID, 10)))
	prefix := "winevent_"
	if format == ingest.FormatSysmonXML {
		prefix = "sysmon_"
	}
	return prefix + hex.EncodeToString(digest[:12])
}

type quarantineRecord struct {
	Channel string
	Reason  string
	Raw     []byte
}

func (s *WindowsEventSource) writeQuarantine(record quarantineRecord) {
	if err := os.MkdirAll(s.quarantineDir, 0o700); err != nil {
		return
	}
	digest := sha256.Sum256(record.Raw)
	name := fmt.Sprintf("%d-%s.xml", s.now().UTC().UnixNano(), hex.EncodeToString(digest[:8]))
	// #nosec G306 -- quarantine payloads are written 0600 below via WriteFile mode.
	_ = os.WriteFile(filepath.Join(s.quarantineDir, name), record.Raw, 0o600)
}

// quarantineStream preserves an entire undecodable stdout stream so the raw
// bytes stay available for analysis instead of being discarded.
func (s *WindowsEventSource) quarantineStream(raw []byte, cause error) {
	s.quarantined++
	if err := os.MkdirAll(s.quarantineDir, 0o700); err != nil {
		return
	}
	digest := sha256.Sum256(raw)
	name := fmt.Sprintf("stream-%d-%s.bin", s.now().UTC().UnixNano(), hex.EncodeToString(digest[:8]))
	_ = os.WriteFile(filepath.Join(s.quarantineDir, name), raw, 0o600)
	_ = os.WriteFile(filepath.Join(s.quarantineDir, name+".reason"), []byte(cause.Error()), 0o600)
}

func readCheckpointFile(name string) (uint64, error) {
	// #nosec G304 -- the checkpoint path is derived from the trusted state directory.
	body, err := os.ReadFile(name)
	if err != nil {
		return 0, err
	}
	value, err := strconv.ParseUint(strings.TrimSpace(string(body)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse checkpoint %q: %w", filepath.Base(name), err)
	}
	return value, nil
}

// writeCheckpointFile persists a cursor atomically and durably: the value is
// fsynced into a temporary file and then renamed over the checkpoint.
func writeCheckpointFile(name, pattern string, cursor uint64) error {
	temporary, err := os.CreateTemp(filepath.Dir(name), pattern)
	if err != nil {
		return fmt.Errorf("create checkpoint: %w", err)
	}
	temporaryName := temporary.Name()
	defer func() { _ = os.Remove(temporaryName) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("secure checkpoint: %w", err)
	}
	if _, err := temporary.WriteString(strconv.FormatUint(cursor, 10)); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write checkpoint: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync checkpoint: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close checkpoint: %w", err)
	}
	if err := os.Rename(temporaryName, name); err != nil {
		return fmt.Errorf("commit checkpoint: %w", err)
	}
	return nil
}
