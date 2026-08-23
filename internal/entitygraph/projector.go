package entitygraph

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/kcsp/platform/internal/core"
)

func Project(event core.CanonicalEvent) core.EntityProjection {
	observedAt := event.EventTime.UTC()
	if observedAt.IsZero() {
		observedAt = event.IngestTime.UTC()
	}
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	risk := eventRisk(event.Severity)
	entities := map[string]core.SecurityEntity{}
	order := []string{}
	add := func(kind core.EntityType, key, name, label string, attributes map[string]string) string {
		key = normalizedKey(key)
		if key == "" {
			return ""
		}
		id := stableID("ent", string(kind), key)
		if _, exists := entities[id]; exists {
			return id
		}
		if strings.TrimSpace(name) == "" {
			name = key
		}
		entities[id] = core.SecurityEntity{
			ID: id, TenantID: event.TenantID, Type: kind, NaturalKey: key,
			DisplayName: strings.TrimSpace(name), Label: strings.TrimSpace(label), RiskScore: risk,
			Attributes: cleanAttributes(attributes), FirstSeen: observedAt, LastSeen: observedAt,
			ObservationCount: 1, LastEventID: event.ID, Version: 1,
		}
		order = append(order, id)
		return id
	}

	userKey := firstNonEmpty(event.User.ID, event.User.Name)
	userID := add(core.EntityTypeUser, userKey, event.User.Name, "identity", map[string]string{"source_id": event.User.ID})
	deviceKey := firstNonEmpty(event.Device.ID, event.Device.Hostname)
	deviceID := add(core.EntityTypeDevice, deviceKey, event.Device.Hostname, event.Device.Department, map[string]string{"source_id": event.Device.ID, "department": event.Device.Department})
	srcIP := canonicalIP(event.SrcEndpoint.IP)
	dstIP := canonicalIP(event.DstEndpoint.IP)
	srcIPID := add(core.EntityTypeIP, srcIP, srcIP, "source endpoint", nil)
	dstIPID := add(core.EntityTypeIP, dstIP, dstIP, "destination endpoint", nil)
	processKey := ""
	if strings.TrimSpace(event.Process.Name) != "" {
		processKey = firstNonEmpty(deviceKey, "unknown-device") + "|" + event.Process.Name
	}
	processID := add(core.EntityTypeProcess, processKey, event.Process.Name, event.Device.Hostname, map[string]string{"command_line": event.Process.CommandLine})
	applicationKey := strings.Join([]string{event.Source.Vendor, event.Source.Product, event.Source.Type}, "|")
	applicationID := add(core.EntityTypeApplication, applicationKey, firstNonEmpty(event.Source.Product, event.Source.Type), event.Source.Vendor, map[string]string{"vendor": event.Source.Vendor, "product": event.Source.Product, "source_type": event.Source.Type})
	collectorID := add(core.EntityTypeService, event.CollectorID, event.CollectorID, "collector", map[string]string{"service_role": "collector"})

	relations := map[string]core.EntityRelation{}
	relationOrder := []string{}
	connect := func(kind, sourceID, targetID string, attributes map[string]string) {
		if sourceID == "" || targetID == "" || sourceID == targetID {
			return
		}
		id := stableID("rel", kind, sourceID, targetID)
		if _, exists := relations[id]; exists {
			return
		}
		relations[id] = core.EntityRelation{
			ID: id, TenantID: event.TenantID, Type: kind, SourceEntityID: sourceID, TargetEntityID: targetID,
			Attributes: cleanAttributes(attributes), FirstSeen: observedAt, LastSeen: observedAt,
			ObservationCount: 1, LastEventID: event.ID, Version: 1,
		}
		relationOrder = append(relationOrder, id)
	}

	userDeviceRelation := "OBSERVED_ON"
	category := strings.ToLower(event.Category + " " + event.ActivityName)
	if strings.Contains(category, "auth") || strings.Contains(category, "login") || strings.Contains(category, "logon") {
		userDeviceRelation = "LOGIN_FROM"
	}
	connect(userDeviceRelation, userID, deviceID, map[string]string{"category": event.Category})
	connect("HAS_IP", deviceID, srcIPID, nil)
	connect("RUNS_ON", processID, deviceID, nil)
	connect("EXECUTED", userID, processID, nil)
	connect("CONNECTED_TO", srcIPID, dstIPID, map[string]string{"activity": event.ActivityName})
	connect("COLLECTS_FROM", collectorID, applicationID, nil)
	for _, entityID := range []string{userID, deviceID, srcIPID, dstIPID, processID} {
		connect("OBSERVED_BY", entityID, applicationID, nil)
	}

	projection := core.EntityProjection{Entities: make([]core.SecurityEntity, 0, len(order)), Relations: make([]core.EntityRelation, 0, len(relationOrder))}
	for _, id := range order {
		projection.Entities = append(projection.Entities, entities[id])
	}
	for _, id := range relationOrder {
		projection.Relations = append(projection.Relations, relations[id])
	}
	return projection
}

func stableID(prefix string, parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return prefix + "_" + hex.EncodeToString(sum[:12])
}

func normalizedKey(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func canonicalIP(value string) string {
	parsed := net.ParseIP(strings.TrimSpace(value))
	if parsed == nil {
		return ""
	}
	return parsed.String()
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}

func cleanAttributes(input map[string]string) map[string]string {
	if len(input) == 0 {
		return map[string]string{}
	}
	result := make(map[string]string, len(input))
	for key, value := range input {
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if key == "" || value == "" {
			continue
		}
		if len(value) > 1024 {
			value = value[:1024]
		}
		result[key] = value
	}
	return result
}

func eventRisk(value interface{}) int {
	normalized := strings.ToUpper(strings.TrimSpace(fmt.Sprint(value)))
	if numeric, err := strconv.Atoi(normalized); err == nil {
		if numeric < 0 {
			return 0
		}
		if numeric > 100 {
			return 100
		}
		return min(100, numeric*20)
	}
	switch normalized {
	case "CRITICAL":
		return 90
	case "HIGH":
		return 70
	case "MEDIUM":
		return 45
	case "LOW":
		return 20
	default:
		return 0
	}
}
