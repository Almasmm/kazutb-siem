package parser

import (
	"context"
	"encoding/xml"
	"fmt"
	"net"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/ingest"
)

const (
	sysmonParserID      = "microsoft-sysmon-xml"
	sysmonParserVersion = "1.0.0"
)

type SysmonXML struct{}

type sysmonEventXML struct {
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
	EventData struct {
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
}

func (SysmonXML) Parse(_ context.Context, envelope ingest.RawEnvelope) (core.CanonicalEvent, error) {
	payload := envelope.PayloadBytes()
	var source sysmonEventXML
	if err := xml.Unmarshal(payload, &source); err != nil {
		return core.CanonicalEvent{}, fmt.Errorf("%w: decode Sysmon XML: %v", ErrParse, err)
	}
	if !strings.Contains(strings.ToLower(source.System.Provider.Name), "sysmon") {
		return core.CanonicalEvent{}, fmt.Errorf("%w: XML provider %q is not Sysmon", ErrParse, source.System.Provider.Name)
	}
	eventCode, err := strconv.Atoi(strings.TrimSpace(source.System.EventID))
	if err != nil || eventCode <= 0 {
		return core.CanonicalEvent{}, fmt.Errorf("%w: invalid Sysmon event ID %q", ErrParse, source.System.EventID)
	}
	fields := make(map[string]string, len(source.EventData.Data))
	for _, field := range source.EventData.Data {
		fields[strings.TrimSpace(field.Name)] = strings.TrimSpace(field.Value)
	}
	eventTime := envelope.EventTimestamp.UTC()
	if parsed, parseErr := time.Parse(time.RFC3339Nano, strings.TrimSpace(source.System.TimeCreated.SystemTime)); parseErr == nil {
		eventTime = parsed.UTC()
	}
	if eventTime.IsZero() {
		eventTime = envelope.ReceivedAt.UTC()
	}
	category, activity, classUID := sysmonClassification(eventCode)
	event := core.CanonicalEvent{
		ID: envelope.EventID, TenantID: envelope.TenantID, CollectorID: envelope.CollectorID,
		EventTime: eventTime, IngestTime: envelope.ReceivedAt.UTC(), Category: category, ActivityName: activity,
		Source: core.EventSource{Vendor: "Microsoft", Product: "Sysmon", Type: "endpoint"},
		Schema: core.SchemaRef{OCSFVersion: "1.4.0", ClassUID: classUID}, Confidence: 85,
		User:   core.UserRef{Name: first(fields, "User", "SubjectUserName")},
		Device: core.DeviceRef{Hostname: source.System.Computer},
		Process: core.ProcessRef{
			Name: windowsBase(fields["Image"]), PID: parseInteger(fields["ProcessId"]),
			CommandLine: fields["CommandLine"], ParentName: windowsBase(fields["ParentImage"]),
		},
		SrcEndpoint:    core.EndpointRef{IP: validIP(fields["SourceIp"]), Port: parseInteger(fields["SourcePort"]), Hostname: fields["SourceHostname"]},
		DstEndpoint:    core.EndpointRef{IP: validIP(fields["DestinationIp"]), Port: parseInteger(fields["DestinationPort"]), Hostname: first(fields, "DestinationHostname", "QueryName")},
		SecurityResult: core.SecurityResult{Action: strings.ToLower(fields["Action"]), Outcome: strings.ToLower(fields["Status"])},
		Raw:            core.RawRef{Message: string(payload), Hash: envelope.RawHash, Reference: "clickhouse://raw/" + envelope.TenantID + "/" + envelope.EventID},
		Parser:         core.ParserRef{ID: sysmonParserID, Version: sysmonParserVersion},
		Metadata: map[string]interface{}{
			"sysmon_event_id": eventCode, "event_record_id": source.System.EventRecordID,
			"channel": source.System.Channel, "fields": fields,
		},
	}
	if event.Category == "process_activity" && event.Process.Name == "" {
		return core.CanonicalEvent{}, fmt.Errorf("%w: Sysmon process event has no Image field", ErrParse)
	}
	return event, nil
}

func sysmonClassification(eventID int) (string, string, int) {
	switch eventID {
	case 1:
		return "process_activity", "Process created", 1007
	case 3:
		return "network_activity", "Network connection", 4001
	case 11:
		return "file_activity", "File created", 1001
	case 13:
		return "registry_activity", "Registry value modified", 1000
	case 22:
		return "dns_activity", "DNS query", 4003
	case 25:
		return "process_activity", "Process tampering", 1007
	default:
		return "system_activity", fmt.Sprintf("Sysmon event %d", eventID), 1000
	}
}

func parseInteger(value string) int {
	parsed, err := strconv.ParseInt(strings.TrimSpace(value), 0, 32)
	if err != nil {
		return 0
	}
	return int(parsed)
}

func validIP(value string) string {
	value = strings.TrimSpace(value)
	if net.ParseIP(value) == nil {
		return ""
	}
	return value
}

func windowsBase(value string) string {
	return path.Base(strings.ReplaceAll(strings.TrimSpace(value), `\`, "/"))
}

func first(fields map[string]string, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(fields[key]); value != "" {
			return value
		}
	}
	return ""
}
