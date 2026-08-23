package parser

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/ingest"
)

// GenericJSON normalizes common vendor-neutral JSON keys while retaining the
// complete decoded object in metadata for parser-studio refinement.
type GenericJSON struct{}

func (GenericJSON) Parse(_ context.Context, envelope ingest.RawEnvelope) (core.CanonicalEvent, error) {
	decoder := json.NewDecoder(strings.NewReader(string(envelope.PayloadBytes())))
	decoder.UseNumber()
	var source map[string]interface{}
	if err := decoder.Decode(&source); err != nil || len(source) == 0 {
		return core.CanonicalEvent{}, fmt.Errorf("%w: generic JSON event must be a non-empty object", ErrParse)
	}
	flat := map[string]string{}
	flattenGenericJSON("", source, flat)
	message := genericField(flat, "message", "msg", "description", "event.original")
	explicitCategory := strings.ToLower(genericField(flat, "category", "event.category", "event_category"))
	activity := genericField(flat, "activity_name", "event.action", "action", "event_type", "event.type", "type", "name", "message")
	category, fallbackActivity, classUID, sourceType := telemetryClass(strings.Join([]string{explicitCategory, activity, message}, " "))
	if normalized := genericCategory(explicitCategory); normalized != "" {
		category = normalized
		_, _, classUID, sourceType = telemetryClass(category)
	}
	if activity == "" {
		activity = fallbackActivity
	}
	vendor := genericField(flat, "vendor", "source.vendor", "observer.vendor")
	product := genericField(flat, "product", "source.product", "observer.product", "service.name", "application")
	if vendor == "" {
		vendor = "Generic"
	}
	if product == "" {
		product = "JSON"
	}
	if declared := genericField(flat, "source.type", "source_type", "observer.type"); declared != "" {
		sourceType = declared
	}
	event := xdrEvent(envelope, "generic-json", vendor, product, sourceType, category, activity, classUID)
	event.SrcEndpoint = core.EndpointRef{
		IP:       validIP(genericField(flat, "src_ip", "source_ip", "source.ip", "client.ip", "network.src_ip")),
		Port:     parseInteger(genericField(flat, "src_port", "source_port", "source.port", "client.port", "network.src_port")),
		Hostname: genericField(flat, "src_host", "source_host", "source.hostname", "client.domain"),
	}
	event.DstEndpoint = core.EndpointRef{
		IP:       validIP(genericField(flat, "dst_ip", "dest_ip", "destination_ip", "destination.ip", "server.ip", "network.dst_ip")),
		Port:     parseInteger(genericField(flat, "dst_port", "dest_port", "destination_port", "destination.port", "server.port", "network.dst_port")),
		Hostname: genericField(flat, "dst_host", "destination_host", "destination.hostname", "server.domain", "domain", "query"),
	}
	event.User.ID = genericField(flat, "user.id", "user_id", "uid", "subject.id")
	event.User.Name = genericField(flat, "user.name", "username", "user", "account", "subject.name")
	event.Device.ID = genericField(flat, "device.id", "device_id", "host.id", "observer.id")
	event.Device.Hostname = genericField(flat, "device.hostname", "hostname", "host.name", "observer.hostname")
	event.Device.IP = validIP(genericField(flat, "device.ip", "host.ip", "observer.ip"))
	event.Process.Name = genericField(flat, "process.name", "process_name", "exe", "executable")
	event.Process.CommandLine = genericField(flat, "process.command_line", "command_line", "cmdline", "command")
	event.SecurityResult.Action = strings.ToLower(genericField(flat, "security_result.action", "event.outcome", "outcome", "action", "disposition"))
	severity := parseInteger(genericField(flat, "severity", "severity_id", "event.severity", "level", "priority"))
	if severity > 0 && severity <= 10 {
		severity *= 10
	}
	if severity == 0 {
		severity = 20
	}
	event.Severity = boundedScore(severity)
	event.Confidence = 70
	event.Metadata = source
	return event, nil
}

func flattenGenericJSON(prefix string, value interface{}, result map[string]string) {
	switch typed := value.(type) {
	case map[string]interface{}:
		for key, item := range typed {
			key = strings.ToLower(strings.TrimSpace(key))
			path := key
			if prefix != "" {
				path = prefix + "." + key
			}
			flattenGenericJSON(path, item, result)
		}
	case []interface{}:
		for index, item := range typed {
			flattenGenericJSON(fmt.Sprintf("%s.%d", prefix, index), item, result)
		}
	case nil:
	default:
		result[prefix] = strings.TrimSpace(fmt.Sprint(typed))
	}
}

func genericField(fields map[string]string, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(fields[strings.ToLower(key)]); value != "" {
			return value
		}
	}
	return ""
}

func genericCategory(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch {
	case containsAny(value, "auth", "login", "logon", "identity"):
		return "authentication"
	case containsAny(value, "dns"):
		return "dns_activity"
	case containsAny(value, "http", "web", "url"):
		return "web_activity"
	case containsAny(value, "network", "firewall", "flow", "connection"):
		return "network_activity"
	case containsAny(value, "process", "execution"):
		return "process_activity"
	case containsAny(value, "file"):
		return "file_activity"
	case containsAny(value, "system", "host"):
		return "system_activity"
	default:
		return ""
	}
}
