package parser

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/ingest"
)

const (
	syslogParserID = "ietf-syslog"
	cefParserID    = "arcsite-cef"
	leefParserID   = "ibm-leef"
)

var (
	rfc5424Pattern = regexp.MustCompile(`^<([0-9]{1,3})>([0-9]{1,3})\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)$`)
	rfc3164Pattern = regexp.MustCompile(`^<([0-9]{1,3})>([A-Z][a-z]{2}\s+[ 0-9][0-9]\s+[0-9:]{8})\s+(\S+)\s+(.+)$`)
	cefKeyPattern  = regexp.MustCompile(`(?:^|\s)([A-Za-z][A-Za-z0-9_.-]*)=`)
)

type Syslog struct{}

func (Syslog) Parse(_ context.Context, envelope ingest.RawEnvelope) (core.CanonicalEvent, error) {
	raw := strings.TrimSpace(string(envelope.PayloadBytes()))
	parsed, err := parseSyslog(raw, envelope.ReceivedAt)
	if err != nil {
		return core.CanonicalEvent{}, err
	}
	category, activity, classUID, sourceType := telemetryClass(parsed.Message + " " + parsed.App)
	event := xdrEvent(envelope, syslogParserID, "IETF", firstNonEmpty(parsed.App, "Syslog"), sourceType, category, activity, classUID)
	event.EventTime = parsed.Timestamp
	event.Device.Hostname = parsed.Hostname
	event.Severity = syslogSeverity(parsed.Priority % 8)
	fields := looseFields(parsed.Message)
	event.SrcEndpoint, event.DstEndpoint = endpointsFromFields(fields, parsed.Message)
	event.User.Name = firstField(fields, "user", "username", "account")
	event.SecurityResult = core.SecurityResult{Action: strings.ToLower(firstField(fields, "action", "act")), Outcome: strings.ToLower(firstField(fields, "outcome", "result", "status"))}
	event.Metadata = map[string]interface{}{
		"facility": parsed.Priority / 8, "syslog_severity": parsed.Priority % 8,
		"app_name": parsed.App, "process_id": parsed.ProcessID, "message_id": parsed.MessageID,
	}
	return event, nil
}

type syslogRecord struct {
	Priority  int
	Timestamp time.Time
	Hostname  string
	App       string
	ProcessID string
	MessageID string
	Message   string
}

func parseSyslog(raw string, fallback time.Time) (syslogRecord, error) {
	if match := rfc5424Pattern.FindStringSubmatch(raw); match != nil {
		priority, _ := strconv.Atoi(match[1])
		if priority > 191 || match[2] != "1" {
			return syslogRecord{}, fmt.Errorf("%w: unsupported syslog priority or version", ErrParse)
		}
		message := match[8]
		if strings.HasPrefix(message, "- ") {
			message = strings.TrimPrefix(message, "- ")
		} else if strings.HasPrefix(message, "[") {
			if end := strings.LastIndex(message, "] "); end >= 0 {
				message = message[end+2:]
			}
		}
		return syslogRecord{Priority: priority, Timestamp: parseTelemetryTime(match[3], fallback), Hostname: dashEmpty(match[4]), App: dashEmpty(match[5]), ProcessID: dashEmpty(match[6]), MessageID: dashEmpty(match[7]), Message: message}, nil
	}
	if match := rfc3164Pattern.FindStringSubmatch(raw); match != nil {
		priority, _ := strconv.Atoi(match[1])
		if priority > 191 {
			return syslogRecord{}, fmt.Errorf("%w: invalid syslog priority", ErrParse)
		}
		app, processID, message := splitLegacyTag(match[4])
		return syslogRecord{Priority: priority, Timestamp: parseTelemetryTime(strings.Join(strings.Fields(match[2]), " "), fallback), Hostname: match[3], App: app, ProcessID: processID, Message: message}, nil
	}
	return syslogRecord{}, fmt.Errorf("%w: message is neither RFC 5424 nor RFC 3164 syslog", ErrParse)
}

func splitLegacyTag(value string) (string, string, string) {
	tag, message, found := strings.Cut(value, ":")
	if !found {
		return "Syslog", "", value
	}
	app := strings.TrimSpace(tag)
	processID := ""
	if open := strings.LastIndex(app, "["); open >= 0 && strings.HasSuffix(app, "]") {
		processID = strings.TrimSuffix(app[open+1:], "]")
		app = app[:open]
	}
	return app, processID, strings.TrimSpace(message)
}

func syslogSeverity(value int) int {
	return []int{100, 95, 85, 70, 50, 35, 20, 10}[boundedScore(value)%8]
}

func dashEmpty(value string) string {
	if value == "-" {
		return ""
	}
	return value
}

type CEF struct{}

func (CEF) Parse(_ context.Context, envelope ingest.RawEnvelope) (core.CanonicalEvent, error) {
	raw := strings.TrimSpace(string(envelope.PayloadBytes()))
	if !strings.HasPrefix(raw, "CEF:") {
		return core.CanonicalEvent{}, fmt.Errorf("%w: CEF prefix is required", ErrParse)
	}
	parts := splitEscapedN(strings.TrimPrefix(raw, "CEF:"), '|', 8)
	if len(parts) != 8 || strings.TrimSpace(parts[1]) == "" || strings.TrimSpace(parts[2]) == "" {
		return core.CanonicalEvent{}, fmt.Errorf("%w: invalid CEF header", ErrParse)
	}
	fields := parseCEFExtension(parts[7])
	category, _, classUID, _ := telemetryClass(parts[2] + " " + parts[5] + " " + parts[6])
	event := xdrEvent(envelope, cefParserID, parts[1], parts[2], "network", category, firstNonEmpty(parts[5], "CEF event"), classUID)
	event.Severity = cefSeverity(parts[6])
	event.SrcEndpoint, event.DstEndpoint = endpointsFromFields(fields, parts[7])
	event.User.Name = firstField(fields, "suser", "duser", "user", "requestClientApplication")
	event.Device.Hostname = firstField(fields, "dvchost", "devicehostname")
	event.SecurityResult = core.SecurityResult{Action: strings.ToLower(firstField(fields, "act", "action")), Outcome: strings.ToLower(firstField(fields, "outcome", "reason"))}
	if timestamp := firstField(fields, "rt", "start", "end"); timestamp != "" {
		event.EventTime = parseTelemetryTime(timestamp, event.EventTime)
	}
	event.Metadata = map[string]interface{}{"cef_version": parts[0], "device_version": parts[3], "signature_id": parts[4], "extensions": fields}
	return event, nil
}

func splitEscapedN(value string, separator byte, maximum int) []string {
	result := make([]string, 0, maximum)
	var current strings.Builder
	escaped := false
	for index := 0; index < len(value); index++ {
		character := value[index]
		if escaped {
			if character != separator && character != '\\' {
				current.WriteByte('\\')
			}
			current.WriteByte(character)
			escaped = false
			continue
		}
		if character == '\\' {
			escaped = true
			continue
		}
		if character == separator && len(result) < maximum-1 {
			result = append(result, current.String())
			current.Reset()
			continue
		}
		current.WriteByte(character)
	}
	if escaped {
		current.WriteByte('\\')
	}
	return append(result, current.String())
}

func parseCEFExtension(value string) map[string]string {
	result := map[string]string{}
	matches := cefKeyPattern.FindAllStringSubmatchIndex(value, -1)
	for index, match := range matches {
		valueStart := match[1]
		if index+1 < len(matches) {
			valueStart = matches[index+1][0]
		}
		result[strings.ToLower(value[match[2]:match[3]])] = unquoteField(strings.TrimSpace(value[match[1]:valueStart]))
	}
	return result
}

func cefSeverity(value string) int {
	if parsed, err := strconv.Atoi(strings.TrimSpace(value)); err == nil {
		return boundedScore(parsed * 10)
	}
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "very-high", "critical":
		return 95
	case "high":
		return 80
	case "medium":
		return 55
	case "low":
		return 25
	default:
		return 10
	}
}

type LEEF struct{}

func (LEEF) Parse(_ context.Context, envelope ingest.RawEnvelope) (core.CanonicalEvent, error) {
	raw := strings.TrimSpace(string(envelope.PayloadBytes()))
	if !strings.HasPrefix(raw, "LEEF:") {
		return core.CanonicalEvent{}, fmt.Errorf("%w: LEEF prefix is required", ErrParse)
	}
	parts := strings.SplitN(strings.TrimPrefix(raw, "LEEF:"), "|", 6)
	if len(parts) != 6 || strings.TrimSpace(parts[1]) == "" || strings.TrimSpace(parts[2]) == "" {
		return core.CanonicalEvent{}, fmt.Errorf("%w: invalid LEEF header", ErrParse)
	}
	delimiter, extension := "\t", parts[5]
	if parts[0] == "2.0" {
		if spec, remainder, found := strings.Cut(extension, "|"); found && spec != "" && !strings.Contains(spec, "=") {
			delimiter, extension = leefDelimiter(spec), remainder
		}
	}
	fields := parseDelimitedFields(extension, delimiter)
	category, activity, classUID, _ := telemetryClass(parts[2] + " " + parts[4] + " " + extension)
	event := xdrEvent(envelope, leefParserID, parts[1], parts[2], "network", category, activity, classUID)
	event.SrcEndpoint, event.DstEndpoint = endpointsFromFields(fields, extension)
	event.User.Name = firstField(fields, "usrname", "username", "user")
	event.Device.Hostname = firstField(fields, "devname", "identhostname")
	event.SecurityResult.Action = strings.ToLower(firstField(fields, "action", "cat"))
	event.Severity = cefSeverity(firstField(fields, "sev", "severity"))
	if timestamp := firstField(fields, "devtime", "eventtime", "time"); timestamp != "" {
		event.EventTime = parseTelemetryTime(timestamp, event.EventTime)
	}
	event.Metadata = map[string]interface{}{"leef_version": parts[0], "device_version": parts[3], "event_id": parts[4], "attributes": fields}
	return event, nil
}

func leefDelimiter(spec string) string {
	switch strings.ToLower(spec) {
	case "x09", "0x09", `\t`:
		return "\t"
	case "x7c", "0x7c":
		return "|"
	default:
		if len(spec) == 1 {
			return spec
		}
		return "\t"
	}
}

func parseDelimitedFields(value, delimiter string) map[string]string {
	result := map[string]string{}
	for _, item := range strings.Split(value, delimiter) {
		key, fieldValue, found := strings.Cut(item, "=")
		if found && strings.TrimSpace(key) != "" {
			result[strings.ToLower(strings.TrimSpace(key))] = unquoteField(fieldValue)
		}
	}
	return result
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}
