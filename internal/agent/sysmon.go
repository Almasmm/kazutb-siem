package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/kcsp/platform/internal/ingest"
)

var ErrUnsupportedSource = errors.New("event source is not supported on this operating system")

type SysmonSource struct {
	channel        string
	checkpointFile string
}

func NewSysmonSource(stateDirectory, channel string) (*SysmonSource, error) {
	if strings.TrimSpace(stateDirectory) == "" {
		return nil, errors.New("agent state directory is required")
	}
	if channel == "" {
		channel = "Microsoft-Windows-Sysmon/Operational"
	}
	if err := os.MkdirAll(stateDirectory, 0o700); err != nil {
		return nil, fmt.Errorf("create agent state directory: %w", err)
	}
	return &SysmonSource{channel: channel, checkpointFile: filepath.Join(stateDirectory, "sysmon.checkpoint")}, nil
}

func (s *SysmonSource) Read(ctx context.Context, limit int) ([]Event, error) {
	if runtime.GOOS != "windows" {
		return nil, fmt.Errorf("%w: Sysmon Event Log requires Windows", ErrUnsupportedSource)
	}
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	checkpoint, err := s.checkpoint()
	if err != nil {
		return nil, err
	}
	query := fmt.Sprintf("/q:*[System[(EventRecordID>%d)]]", checkpoint)
	command := exec.CommandContext(ctx, "wevtutil", "qe", s.channel, query, "/f:xml", "/rd:false", fmt.Sprintf("/c:%d", limit))
	output, err := command.CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(output))
		if len(message) > 1024 {
			message = message[:1024]
		}
		return nil, fmt.Errorf("query Sysmon Event Log: %w: %s", err, message)
	}
	return parseSysmonEvents(output, checkpoint)
}

func (s *SysmonSource) Commit(cursor uint64) error {
	if cursor == 0 {
		return errors.New("cannot commit empty Sysmon cursor")
	}
	current, err := s.checkpoint()
	if err != nil {
		return err
	}
	if cursor <= current {
		return nil
	}
	temporary, err := os.CreateTemp(filepath.Dir(s.checkpointFile), ".sysmon-checkpoint-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer func() { _ = os.Remove(name) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.WriteString(strconv.FormatUint(cursor, 10)); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(name, s.checkpointFile)
}

func (s *SysmonSource) checkpoint() (uint64, error) {
	body, err := os.ReadFile(s.checkpointFile)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read Sysmon checkpoint: %w", err)
	}
	value, err := strconv.ParseUint(strings.TrimSpace(string(body)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse Sysmon checkpoint: %w", err)
	}
	return value, nil
}

func parseSysmonEvents(document []byte, after uint64) ([]Event, error) {
	rawEvents := splitEventXML(document)
	events := make([]Event, 0, len(rawEvents))
	for _, raw := range rawEvents {
		var header struct {
			System struct {
				EventRecordID uint64 `xml:"EventRecordID"`
				Computer      string `xml:"Computer"`
				TimeCreated   struct {
					SystemTime string `xml:"SystemTime,attr"`
				} `xml:"TimeCreated"`
			} `xml:"System"`
		}
		if err := xml.Unmarshal(raw, &header); err != nil {
			return nil, fmt.Errorf("decode Sysmon event header: %w", err)
		}
		if header.System.EventRecordID == 0 || header.System.EventRecordID <= after {
			continue
		}
		eventTime, err := time.Parse(time.RFC3339Nano, header.System.TimeCreated.SystemTime)
		if err != nil {
			return nil, fmt.Errorf("parse Sysmon event timestamp: %w", err)
		}
		identity := sha256.Sum256([]byte(strings.ToLower(header.System.Computer) + "|" + strconv.FormatUint(header.System.EventRecordID, 10)))
		events = append(events, Event{
			Format: ingest.FormatSysmonXML, ContentType: "application/xml",
			EventID: "sysmon_" + hex.EncodeToString(identity[:12]), EventTimestamp: eventTime.UTC(),
			Payload: append([]byte(nil), raw...), Cursor: header.System.EventRecordID,
		})
	}
	return events, nil
}

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
