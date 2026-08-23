package agent

import (
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

type WindowsEventSource struct {
	channel        string
	checkpointFile string
}

func NewWindowsEventSource(stateDirectory, channel string) (*WindowsEventSource, error) {
	stateDirectory = strings.TrimSpace(stateDirectory)
	channel = strings.TrimSpace(channel)
	if stateDirectory == "" {
		return nil, errors.New("agent state directory is required")
	}
	if channel == "" || len(channel) > 256 || strings.ContainsAny(channel, "\r\n") {
		return nil, errors.New("valid Windows Event Log channel is required")
	}
	if err := os.MkdirAll(stateDirectory, 0o700); err != nil {
		return nil, fmt.Errorf("create agent state directory: %w", err)
	}
	identity := sha256.Sum256([]byte(strings.ToLower(channel)))
	return &WindowsEventSource{
		channel:        channel,
		checkpointFile: filepath.Join(stateDirectory, "windows-event-"+hex.EncodeToString(identity[:8])+".checkpoint"),
	}, nil
}

func (s *WindowsEventSource) Name() string {
	return "windows-event:" + s.channel
}

func (s *WindowsEventSource) Read(ctx context.Context, limit int) ([]Event, error) {
	if runtime.GOOS != "windows" {
		return nil, fmt.Errorf("%w: Windows Event Log requires Windows", ErrUnsupportedSource)
	}
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	checkpoint, err := s.checkpoint()
	if err != nil {
		return nil, err
	}
	query := fmt.Sprintf("/q:*[System[(EventRecordID>%d)]]", checkpoint)
	// #nosec G204 -- wevtutil is fixed and the validated channel is a discrete argv value; no shell is involved.
	command := exec.CommandContext(ctx, "wevtutil", "qe", s.channel, query, "/f:xml", "/rd:false", fmt.Sprintf("/c:%d", limit))
	output, err := command.CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(output))
		if len(message) > 1024 {
			message = message[:1024]
		}
		return nil, fmt.Errorf("query Windows Event Log channel %q: %w: %s", s.channel, err, message)
	}
	return parseWindowsEvents(output, checkpoint, s.channel)
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
	temporary, err := os.CreateTemp(filepath.Dir(s.checkpointFile), ".windows-event-checkpoint-*")
	if err != nil {
		return fmt.Errorf("create Windows Event Log checkpoint: %w", err)
	}
	name := temporary.Name()
	defer func() { _ = os.Remove(name) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("secure Windows Event Log checkpoint: %w", err)
	}
	if _, err := temporary.WriteString(strconv.FormatUint(event.Cursor, 10)); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write Windows Event Log checkpoint: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync Windows Event Log checkpoint: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close Windows Event Log checkpoint: %w", err)
	}
	if err := os.Rename(name, s.checkpointFile); err != nil {
		return fmt.Errorf("commit Windows Event Log checkpoint: %w", err)
	}
	return nil
}

func (s *WindowsEventSource) checkpoint() (uint64, error) {
	body, err := os.ReadFile(s.checkpointFile)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read Windows Event Log checkpoint: %w", err)
	}
	value, err := strconv.ParseUint(strings.TrimSpace(string(body)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse Windows Event Log checkpoint: %w", err)
	}
	return value, nil
}

func parseWindowsEvents(document []byte, after uint64, configuredChannel string) ([]Event, error) {
	rawEvents := splitEventXML(document)
	events := make([]Event, 0, len(rawEvents))
	for _, raw := range rawEvents {
		var header struct {
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
		if err := xml.Unmarshal(raw, &header); err != nil {
			return nil, fmt.Errorf("decode Windows Event Log header: %w", err)
		}
		if header.System.EventRecordID == 0 || header.System.EventRecordID <= after {
			continue
		}
		computer := strings.TrimSpace(header.System.Computer)
		provider := strings.TrimSpace(header.System.Provider.Name)
		eventCode := strings.TrimSpace(header.System.EventID)
		if computer == "" || provider == "" || eventCode == "" {
			return nil, errors.New("decode Windows Event Log header: computer, provider, and event ID are required")
		}
		eventTime, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(header.System.TimeCreated.SystemTime))
		if err != nil {
			return nil, fmt.Errorf("parse Windows Event Log timestamp: %w", err)
		}
		channel := strings.TrimSpace(header.System.Channel)
		if channel == "" {
			channel = configuredChannel
		}
		hostIdentity := strings.ToLower(computer)
		identity := sha256.Sum256([]byte(hostIdentity + "|" + strings.ToLower(channel) + "|" + strconv.FormatUint(header.System.EventRecordID, 10)))
		events = append(events, Event{
			Format: ingest.FormatWindowsEventXML, ContentType: "application/xml",
			EventID: "winevent_" + hex.EncodeToString(identity[:12]), EventTimestamp: eventTime.UTC(),
			SourceID: "host:" + hostIdentity, SourceAddress: computer,
			Payload: append([]byte(nil), raw...), Cursor: header.System.EventRecordID,
		})
	}
	return events, nil
}
