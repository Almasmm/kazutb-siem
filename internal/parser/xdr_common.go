package parser

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/ingest"
)

var (
	looseKVPattern = regexp.MustCompile(`([A-Za-z][A-Za-z0-9_.-]*)=("(?:\\.|[^"])*"|'(?:\\.|[^'])*'|[^\s]+)`)
	ipPattern      = regexp.MustCompile(`(?:[0-9]{1,3}\.){3}[0-9]{1,3}|[0-9A-Fa-f:]{2,}`)
)

func xdrEvent(envelope ingest.RawEnvelope, parserID, vendor, product, sourceType, category, activity string, classUID int) core.CanonicalEvent {
	eventTime := envelope.EventTimestamp.UTC()
	if eventTime.IsZero() {
		eventTime = envelope.ReceivedAt.UTC()
	}
	ingestTime := envelope.ReceivedAt.UTC()
	if ingestTime.IsZero() {
		ingestTime = eventTime
	}
	return core.CanonicalEvent{
		ID: envelope.EventID, TenantID: envelope.TenantID, CollectorID: envelope.CollectorID,
		EventTime: eventTime, IngestTime: ingestTime, Category: category, ActivityName: activity,
		Source: core.EventSource{Vendor: vendor, Product: product, Type: sourceType},
		Schema: core.SchemaRef{OCSFVersion: "1.4.0", ClassUID: classUID}, Confidence: 75,
		Raw: core.RawRef{Message: string(envelope.PayloadBytes()), Hash: envelope.RawHash,
			Reference: "clickhouse://raw/" + envelope.TenantID + "/" + envelope.EventID},
		Parser:   core.ParserRef{ID: parserID, Version: "1.0.0"},
		Metadata: map[string]interface{}{},
	}
}

func telemetryClass(text string) (string, string, int, string) {
	lower := strings.ToLower(text)
	switch {
	case containsAny(lower, "dns", "named[", "query_a", "qname"):
		return "dns_activity", "DNS activity", 4003, "network"
	case containsAny(lower, "login", "logon", "authentication", "sshd", "pam_", "kerberos", "radius"):
		return "authentication", "Authentication activity", 3002, "identity"
	case containsAny(lower, "process", "execve", "syscall=59", "powershell", "cmd.exe"):
		return "process_activity", "Process activity", 1007, "endpoint"
	case containsAny(lower, "file", "path=", "inode="):
		return "file_activity", "File activity", 1001, "endpoint"
	case containsAny(lower, "http", "url=", "request="):
		return "web_activity", "Web activity", 4002, "network"
	case containsAny(lower, "firewall", "deny", "denied", "blocked", "drop", "accept", "allow", "vpn", "dhcp", "src=", "dst="):
		return "network_activity", "Network activity", 4001, "network"
	default:
		return "system_activity", "System activity", 1000, "system"
	}
}

func containsAny(value string, candidates ...string) bool {
	for _, candidate := range candidates {
		if strings.Contains(value, candidate) {
			return true
		}
	}
	return false
}

func looseFields(value string) map[string]string {
	result := map[string]string{}
	for _, match := range looseKVPattern.FindAllStringSubmatch(value, -1) {
		result[strings.ToLower(match[1])] = unquoteField(match[2])
	}
	return result
}

func unquoteField(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 2 && (value[0] == '"' && value[len(value)-1] == '"' || value[0] == '\'' && value[len(value)-1] == '\'') {
		value = value[1 : len(value)-1]
	}
	value = strings.ReplaceAll(value, `\=`, `=`)
	value = strings.ReplaceAll(value, `\ `, ` `)
	value = strings.ReplaceAll(value, `\\`, `\`)
	return value
}

func firstField(fields map[string]string, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(fields[strings.ToLower(key)]); value != "" {
			return value
		}
	}
	return ""
}

func endpointsFromFields(fields map[string]string, message string) (core.EndpointRef, core.EndpointRef) {
	source := core.EndpointRef{
		IP:       validIP(firstField(fields, "src", "src_ip", "source", "sourceip", "ipaddress", "addr")),
		Port:     parseInteger(firstField(fields, "spt", "src_port", "srcport", "sourceport", "sport")),
		Hostname: firstField(fields, "shost", "src_host", "sourcehostname", "hostname"),
	}
	destination := core.EndpointRef{
		IP:       validIP(firstField(fields, "dst", "dest_ip", "destination", "destinationip")),
		Port:     parseInteger(firstField(fields, "dpt", "dst_port", "dstport", "dest_port", "destport", "destinationport", "dport")),
		Hostname: firstField(fields, "dhost", "dst_host", "destinationhostname"),
	}
	if source.IP == "" || destination.IP == "" {
		for _, candidate := range ipPattern.FindAllString(message, -1) {
			candidate = validIP(candidate)
			if candidate == "" {
				continue
			}
			if source.IP == "" {
				source.IP = candidate
			} else if destination.IP == "" && candidate != source.IP {
				destination.IP = candidate
			}
		}
	}
	return source, destination
}

func parseTelemetryTime(value string, fallback time.Time) time.Time {
	value = strings.TrimSpace(value)
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "Jan 2 15:04:05", "Jan 02 15:04:05"} {
		if parsed, err := time.Parse(layout, value); err == nil {
			if parsed.Year() == 0 {
				year := fallback.UTC().Year()
				parsed = time.Date(year, parsed.Month(), parsed.Day(), parsed.Hour(), parsed.Minute(), parsed.Second(), 0, time.UTC)
			}
			return parsed.UTC()
		}
	}
	if numeric, err := strconv.ParseFloat(value, 64); err == nil && numeric > 0 {
		seconds := int64(numeric)
		nanos := int64((numeric - float64(seconds)) * float64(time.Second))
		if seconds > 10_000_000_000 {
			seconds, nanos = seconds/1000, (seconds%1000)*int64(time.Millisecond)
		}
		return time.Unix(seconds, nanos).UTC()
	}
	return fallback.UTC()
}

func boundedScore(value int) int {
	if value < 0 {
		return 0
	}
	if value > 100 {
		return 100
	}
	return value
}
