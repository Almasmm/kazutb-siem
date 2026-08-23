package agent

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

type JournalSource struct {
	checkpointFile string
	matches        []string
}

func NewJournalSource(stateDirectory string, matches []string) (*JournalSource, error) {
	stateDirectory = strings.TrimSpace(stateDirectory)
	if stateDirectory == "" {
		return nil, errors.New("agent state directory is required")
	}
	if err := os.MkdirAll(stateDirectory, 0o700); err != nil {
		return nil, fmt.Errorf("create agent state directory: %w", err)
	}
	validated := make([]string, 0, len(matches))
	for _, match := range matches {
		match = strings.TrimSpace(match)
		if match == "" {
			continue
		}
		if !validJournalMatch(match) {
			return nil, fmt.Errorf("invalid journald match %q; expected FIELD=value", match)
		}
		validated = append(validated, match)
	}
	return &JournalSource{
		checkpointFile: filepath.Join(stateDirectory, "journald.checkpoint"),
		matches:        validated,
	}, nil
}

func validJournalMatch(match string) bool {
	field, value, found := strings.Cut(match, "=")
	if !found || len(field) == 0 || len(field) > 64 || value == "" || strings.ContainsAny(value, "\x00\r\n") {
		return false
	}
	for index := 0; index < len(field); index++ {
		character := field[index]
		if character == '_' || (character >= 'A' && character <= 'Z') || (index > 0 && character >= '0' && character <= '9') {
			continue
		}
		return false
	}
	return true
}

func (s *JournalSource) Name() string {
	return "journald"
}

func (s *JournalSource) Read(ctx context.Context, limit int) ([]Event, error) {
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("%w: journald requires Linux", ErrUnsupportedSource)
	}
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	checkpoint, err := s.checkpoint()
	if err != nil {
		return nil, err
	}
	arguments := []string{"--output=json", "--no-pager", "--quiet", "--utc"}
	if checkpoint == "" {
		arguments = append(arguments, "--lines", strconv.Itoa(limit))
	} else {
		arguments = append(arguments, "--after-cursor", checkpoint)
	}
	arguments = append(arguments, s.matches...)
	commandContext, cancel := context.WithCancel(ctx)
	defer cancel()
	command := exec.CommandContext(commandContext, "journalctl", arguments...)
	stdout, err := command.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("open journalctl output: %w", err)
	}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		return nil, fmt.Errorf("start journalctl: %w", err)
	}

	events := make([]Event, 0, limit)
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 64*1024), ingest.MaxEventBytes)
	for scanner.Scan() {
		event, parseErr := parseJournalEvent(scanner.Bytes())
		if parseErr != nil {
			cancel()
			_ = command.Wait()
			return nil, parseErr
		}
		events = append(events, event)
		if len(events) == limit {
			cancel()
			break
		}
	}
	if err := scanner.Err(); err != nil {
		cancel()
		_ = command.Wait()
		return nil, fmt.Errorf("read journalctl output: %w", err)
	}
	waitErr := command.Wait()
	if waitErr != nil && len(events) < limit && ctx.Err() == nil {
		message := strings.TrimSpace(stderr.String())
		if len(message) > 1024 {
			message = message[:1024]
		}
		return nil, fmt.Errorf("query journald: %w: %s", waitErr, message)
	}
	return events, nil
}

func (s *JournalSource) CommitEvent(event Event) error {
	checkpoint := strings.TrimSpace(event.Checkpoint)
	if checkpoint == "" || strings.ContainsAny(checkpoint, "\r\n") {
		return errors.New("cannot commit empty or invalid journald checkpoint")
	}
	current, err := s.checkpoint()
	if err != nil {
		return err
	}
	if checkpoint == current {
		return nil
	}
	temporary, err := os.CreateTemp(filepath.Dir(s.checkpointFile), ".journald-checkpoint-*")
	if err != nil {
		return fmt.Errorf("create journald checkpoint: %w", err)
	}
	name := temporary.Name()
	defer func() { _ = os.Remove(name) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("secure journald checkpoint: %w", err)
	}
	if _, err := temporary.WriteString(checkpoint); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write journald checkpoint: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync journald checkpoint: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close journald checkpoint: %w", err)
	}
	if err := os.Rename(name, s.checkpointFile); err != nil {
		return fmt.Errorf("commit journald checkpoint: %w", err)
	}
	return nil
}

func (s *JournalSource) checkpoint() (string, error) {
	body, err := os.ReadFile(s.checkpointFile)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read journald checkpoint: %w", err)
	}
	checkpoint := strings.TrimSpace(string(body))
	if strings.ContainsAny(checkpoint, "\r\n") {
		return "", errors.New("stored journald checkpoint is invalid")
	}
	return checkpoint, nil
}

func parseJournalEvent(raw []byte) (Event, error) {
	if len(raw) == 0 || len(raw) > ingest.MaxEventBytes || !json.Valid(raw) {
		return Event{}, errors.New("decode journald event: valid bounded JSON is required")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return Event{}, fmt.Errorf("decode journald event: %w", err)
	}
	cursor := journalField(fields, "__CURSOR")
	if cursor == "" || strings.ContainsAny(cursor, "\r\n") {
		return Event{}, errors.New("decode journald event: __CURSOR is required")
	}
	timestamp := journalField(fields, "_SOURCE_REALTIME_TIMESTAMP")
	if timestamp == "" {
		timestamp = journalField(fields, "__REALTIME_TIMESTAMP")
	}
	microseconds, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil || microseconds <= 0 {
		return Event{}, errors.New("decode journald event: realtime timestamp is required")
	}
	hostname := strings.TrimSpace(journalField(fields, "_HOSTNAME"))
	machineID := strings.TrimSpace(journalField(fields, "_MACHINE_ID"))
	hostIdentity := strings.ToLower(firstJournalValue(machineID, hostname))
	if hostIdentity == "" {
		return Event{}, errors.New("decode journald event: machine or host identity is required")
	}
	identity := sha256.Sum256([]byte(hostIdentity + "|" + cursor))
	return Event{
		Format: ingest.FormatJournaldJSON, ContentType: "application/json",
		EventID:        "journal_" + hex.EncodeToString(identity[:12]),
		EventTimestamp: time.UnixMicro(microseconds).UTC(),
		SourceID:       "host:" + hostIdentity, SourceAddress: hostname,
		Payload: append([]byte(nil), raw...), Checkpoint: cursor,
	}, nil
}

func journalField(fields map[string]json.RawMessage, key string) string {
	raw, found := fields[key]
	if !found {
		return ""
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return text
	}
	var octets []int
	if json.Unmarshal(raw, &octets) == nil {
		decoded := make([]byte, len(octets))
		for index, value := range octets {
			if value < 0 || value > 255 {
				return ""
			}
			decoded[index] = byte(value)
		}
		return string(decoded)
	}
	return ""
}

func firstJournalValue(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}
