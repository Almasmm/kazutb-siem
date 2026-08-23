package parser

import (
	"context"
	"encoding/xml"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/ingest"
)

type WindowsEventXML struct{}

func (WindowsEventXML) Parse(_ context.Context, envelope ingest.RawEnvelope) (core.CanonicalEvent, error) {
	var source sysmonEventXML
	if err := xml.Unmarshal(envelope.PayloadBytes(), &source); err != nil {
		return core.CanonicalEvent{}, fmt.Errorf("%w: decode Windows Event XML: %v", ErrParse, err)
	}
	eventCode, err := strconv.Atoi(strings.TrimSpace(source.System.EventID))
	if err != nil || eventCode <= 0 || strings.TrimSpace(source.System.Provider.Name) == "" {
		return core.CanonicalEvent{}, fmt.Errorf("%w: Windows provider and event ID are required", ErrParse)
	}
	fields := make(map[string]string, len(source.EventData.Data))
	for _, field := range source.EventData.Data {
		fields[strings.TrimSpace(field.Name)] = strings.TrimSpace(field.Value)
	}
	category, activity, classUID, sourceType, severity, outcome := windowsEventClass(eventCode)
	event := xdrEvent(envelope, "microsoft-windows-event-xml", "Microsoft", "Windows Event Log", sourceType, category, activity, classUID)
	if parsed, parseErr := time.Parse(time.RFC3339Nano, strings.TrimSpace(source.System.TimeCreated.SystemTime)); parseErr == nil {
		event.EventTime = parsed.UTC()
	}
	event.Severity = severity
	event.Confidence = 85
	event.User = core.UserRef{ID: first(fields, "TargetUserSid", "SubjectUserSid"), Name: first(fields, "TargetUserName", "SubjectUserName")}
	event.Device.Hostname = source.System.Computer
	event.SrcEndpoint = core.EndpointRef{IP: validIP(first(fields, "IpAddress", "ClientAddress", "SourceAddress")), Port: parseInteger(first(fields, "IpPort", "SourcePort")), Hostname: first(fields, "WorkstationName", "ClientName")}
	event.Process = core.ProcessRef{Name: windowsBase(first(fields, "NewProcessName", "ProcessName", "Application")), PID: parseInteger(first(fields, "NewProcessId", "ProcessId")), CommandLine: first(fields, "CommandLine", "ProcessCommandLine"), ParentName: windowsBase(first(fields, "ParentProcessName", "CreatorProcessName"))}
	event.SecurityResult = core.SecurityResult{Action: strings.ToLower(first(fields, "Action", "Task")), Outcome: outcome}
	event.Metadata = map[string]interface{}{"windows_event_id": eventCode, "event_record_id": source.System.EventRecordID, "channel": source.System.Channel, "provider": source.System.Provider.Name, "fields": fields}
	return event, nil
}

func windowsEventClass(eventID int) (string, string, int, string, int, string) {
	switch eventID {
	case 4624:
		return "authentication", "Windows logon succeeded", 3002, "identity", 20, "success"
	case 4625:
		return "authentication", "Windows logon failed", 3002, "identity", 60, "failure"
	case 4634, 4647:
		return "authentication", "Windows logoff", 3002, "identity", 10, "success"
	case 4648:
		return "authentication", "Explicit credential logon", 3002, "identity", 50, "success"
	case 4688:
		return "process_activity", "Windows process created", 1007, "endpoint", 30, "success"
	case 4720:
		return "account_change", "User account created", 3001, "identity", 55, "success"
	case 4728, 4732, 4756:
		return "account_change", "Member added to security group", 3001, "identity", 65, "success"
	case 4740:
		return "account_change", "User account locked", 3001, "identity", 50, "failure"
	case 4768, 4769:
		return "authentication", "Kerberos ticket requested", 3002, "identity", 25, "success"
	case 4771:
		return "authentication", "Kerberos pre-authentication failed", 3002, "identity", 60, "failure"
	default:
		return "system_activity", fmt.Sprintf("Windows event %d", eventID), 1000, "endpoint", 20, ""
	}
}

type LinuxAudit struct{}

var auditTimestampPattern = regexp.MustCompile(`msg=audit\(([0-9]+(?:\.[0-9]+)?):([0-9]+)\)`)

func (LinuxAudit) Parse(_ context.Context, envelope ingest.RawEnvelope) (core.CanonicalEvent, error) {
	raw := strings.TrimSpace(string(envelope.PayloadBytes()))
	fields := looseFields(raw)
	recordType := strings.ToUpper(firstField(fields, "type"))
	if recordType == "" {
		if prefix, _, found := strings.Cut(raw, " "); found && strings.HasPrefix(prefix, "type=") {
			recordType = strings.ToUpper(strings.TrimPrefix(prefix, "type="))
		}
	}
	if recordType == "" || !strings.Contains(raw, "msg=audit(") {
		return core.CanonicalEvent{}, fmt.Errorf("%w: auditd type and audit timestamp are required", ErrParse)
	}
	category, activity, classUID, sourceType := auditClass(recordType)
	event := xdrEvent(envelope, "linux-auditd", "Linux", "auditd", sourceType, category, activity, classUID)
	if match := auditTimestampPattern.FindStringSubmatch(raw); match != nil {
		event.EventTime = parseTelemetryTime(match[1], event.EventTime)
		event.Metadata["audit_serial"] = match[2]
	}
	event.Severity = 35
	event.User = core.UserRef{ID: firstField(fields, "auid", "uid"), Name: firstField(fields, "acct", "user")}
	event.Device.Hostname = firstField(fields, "hostname", "node")
	event.Process = core.ProcessRef{Name: firstNonEmpty(firstField(fields, "comm"), windowsBase(firstField(fields, "exe"))), PID: parseInteger(firstField(fields, "pid")), ParentName: firstField(fields, "ppid"), CommandLine: firstField(fields, "proctitle", "cmd")}
	event.SrcEndpoint = core.EndpointRef{IP: validIP(firstField(fields, "addr", "src")), Port: parseInteger(firstField(fields, "port"))}
	success := strings.ToLower(firstField(fields, "success", "res"))
	if success == "yes" || success == "success" || success == "1" {
		event.SecurityResult.Outcome = "success"
	} else if success == "no" || success == "failed" || success == "0" {
		event.SecurityResult.Outcome, event.Severity = "failure", 60
	}
	event.SecurityResult.Action = strings.ToLower(firstNonEmpty(firstField(fields, "key"), recordType))
	event.Metadata["record_type"] = recordType
	event.Metadata["syscall"] = firstField(fields, "syscall")
	event.Metadata["executable"] = firstField(fields, "exe")
	event.Metadata["session"] = firstField(fields, "ses")
	return event, nil
}

func auditClass(recordType string) (string, string, int, string) {
	switch recordType {
	case "SYSCALL", "EXECVE", "PROCTITLE":
		return "process_activity", "Linux process activity", 1007, "endpoint"
	case "PATH", "CWD":
		return "file_activity", "Linux file activity", 1001, "endpoint"
	case "USER_AUTH", "USER_LOGIN", "USER_ACCT", "CRED_ACQ", "CRED_DISP":
		return "authentication", "Linux authentication", 3002, "identity"
	case "ADD_USER", "DEL_USER", "USER_MGMT", "GRP_MGMT":
		return "account_change", "Linux account change", 3001, "identity"
	default:
		return "system_activity", "Linux audit " + recordType, 1000, "endpoint"
	}
}
