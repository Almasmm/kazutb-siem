package parser

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/ingest"
)

type JournaldJSON struct{}

func (JournaldJSON) Parse(_ context.Context, envelope ingest.RawEnvelope) (core.CanonicalEvent, error) {
	payload := envelope.PayloadBytes()
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(payload, &fields); err != nil {
		return core.CanonicalEvent{}, fmt.Errorf("%w: decode journald JSON: %v", ErrParse, err)
	}
	cursor := journaldField(fields, "__CURSOR")
	message := strings.TrimSpace(journaldField(fields, "MESSAGE"))
	if cursor == "" || message == "" {
		return core.CanonicalEvent{}, fmt.Errorf("%w: journald cursor and message are required", ErrParse)
	}
	category, activity, classUID, sourceType, severity, outcome := journaldClass(message, journaldField(fields, "SYSLOG_IDENTIFIER"), journaldField(fields, "_COMM"))
	event := xdrEvent(envelope, "linux-journald-json", "Linux", "systemd-journald", sourceType, category, activity, classUID)
	timestamp := firstNonEmpty(journaldField(fields, "_SOURCE_REALTIME_TIMESTAMP"), journaldField(fields, "__REALTIME_TIMESTAMP"))
	if microseconds, err := strconv.ParseInt(timestamp, 10, 64); err == nil && microseconds > 0 {
		event.EventTime = time.UnixMicro(microseconds).UTC()
	}
	event.Severity = max(severity, journaldSeverity(journaldField(fields, "PRIORITY")))
	event.Confidence = 80
	event.User = core.UserRef{
		ID:   firstNonEmpty(journaldField(fields, "_AUDIT_LOGINUID"), journaldField(fields, "_UID")),
		Name: firstNonEmpty(journaldField(fields, "USER"), journaldField(fields, "USERNAME")),
	}
	event.Device.Hostname = journaldField(fields, "_HOSTNAME")
	event.Process = core.ProcessRef{
		Name:        firstNonEmpty(journaldField(fields, "_COMM"), journaldField(fields, "SYSLOG_IDENTIFIER")),
		PID:         parseInteger(journaldField(fields, "_PID")),
		CommandLine: journaldField(fields, "_CMDLINE"),
	}
	event.SecurityResult = core.SecurityResult{
		Action:  strings.ToLower(firstNonEmpty(journaldField(fields, "SYSLOG_IDENTIFIER"), journaldField(fields, "_COMM"))),
		Outcome: outcome,
	}
	event.Metadata = map[string]interface{}{
		"journal_cursor":    cursor,
		"message":           message,
		"systemd_unit":      journaldField(fields, "_SYSTEMD_UNIT"),
		"boot_id":           journaldField(fields, "_BOOT_ID"),
		"transport":         journaldField(fields, "_TRANSPORT"),
		"syslog_identifier": journaldField(fields, "SYSLOG_IDENTIFIER"),
	}
	return event, nil
}

func journaldClass(message, identifier, command string) (string, string, int, string, int, string) {
	search := strings.ToLower(strings.Join([]string{message, identifier, command}, " "))
	if strings.Contains(search, "sudo") || strings.Contains(search, "sshd") || strings.Contains(search, "pam_") || strings.Contains(search, "authentication") || strings.Contains(search, "login") {
		outcome := ""
		severity := 40
		if strings.Contains(search, "failure") || strings.Contains(search, "failed") || strings.Contains(search, "invalid user") || strings.Contains(search, "denied") {
			outcome, severity = "failure", 65
		} else if strings.Contains(search, "accepted") || strings.Contains(search, "success") || strings.Contains(search, "session opened") {
			outcome, severity = "success", 20
		}
		return "authentication", "Linux authentication", 3002, "identity", severity, outcome
	}
	if strings.Contains(search, "started") || strings.Contains(search, "stopped") || strings.Contains(search, "failed unit") {
		return "system_activity", "Linux service activity", 1000, "endpoint", 35, ""
	}
	return "system_activity", "Linux journal event", 1000, "endpoint", 25, ""
}

func journaldSeverity(priority string) int {
	value, err := strconv.Atoi(strings.TrimSpace(priority))
	if err != nil {
		return 0
	}
	switch value {
	case 0:
		return 95
	case 1:
		return 90
	case 2:
		return 80
	case 3:
		return 70
	case 4:
		return 50
	case 5:
		return 35
	case 6:
		return 20
	case 7:
		return 10
	default:
		return 0
	}
}

func journaldField(fields map[string]json.RawMessage, key string) string {
	raw, found := fields[key]
	if !found {
		return ""
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return strings.TrimSpace(text)
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
		return strings.TrimSpace(string(decoded))
	}
	return ""
}
