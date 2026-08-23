package parser

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/ingest"
)

type SuricataEVE struct{}

type suricataEvent struct {
	Timestamp string `json:"timestamp"`
	EventType string `json:"event_type"`
	SrcIP     string `json:"src_ip"`
	SrcPort   int    `json:"src_port"`
	DestIP    string `json:"dest_ip"`
	DestPort  int    `json:"dest_port"`
	Proto     string `json:"proto"`
	AppProto  string `json:"app_proto"`
	FlowID    uint64 `json:"flow_id"`
	Alert     struct {
		Action    string `json:"action"`
		Signature string `json:"signature"`
		Category  string `json:"category"`
		Severity  int    `json:"severity"`
	} `json:"alert"`
	DNS struct {
		Type   string `json:"type"`
		RRName string `json:"rrname"`
		RRType string `json:"rrtype"`
	} `json:"dns"`
	HTTP struct {
		Hostname string `json:"hostname"`
		URL      string `json:"url"`
		Method   string `json:"http_method"`
		Status   int    `json:"status"`
	} `json:"http"`
	TLS struct {
		SNI string `json:"sni"`
	} `json:"tls"`
}

func (SuricataEVE) Parse(_ context.Context, envelope ingest.RawEnvelope) (core.CanonicalEvent, error) {
	var source suricataEvent
	if err := json.Unmarshal(envelope.PayloadBytes(), &source); err != nil {
		return core.CanonicalEvent{}, fmt.Errorf("%w: decode Suricata EVE JSON: %v", ErrParse, err)
	}
	if strings.TrimSpace(source.EventType) == "" || validIP(source.SrcIP) == "" && validIP(source.DestIP) == "" {
		return core.CanonicalEvent{}, fmt.Errorf("%w: Suricata event_type and endpoint are required", ErrParse)
	}
	category, activity, classUID := "network_activity", "Suricata "+source.EventType, 4001
	switch source.EventType {
	case "alert":
		activity = firstNonEmpty(source.Alert.Signature, "Suricata alert")
	case "dns":
		category, activity, classUID = "dns_activity", "DNS "+firstNonEmpty(source.DNS.Type, "activity"), 4003
	case "http":
		category, activity, classUID = "web_activity", firstNonEmpty(source.HTTP.Method, "HTTP")+" request", 4002
	case "tls":
		activity = "TLS session"
	}
	event := xdrEvent(envelope, "oisf-suricata-eve", "OISF", "Suricata", "network", category, activity, classUID)
	event.EventTime = parseTelemetryTime(source.Timestamp, event.EventTime)
	event.SrcEndpoint = core.EndpointRef{IP: validIP(source.SrcIP), Port: source.SrcPort}
	event.DstEndpoint = core.EndpointRef{IP: validIP(source.DestIP), Port: source.DestPort, Hostname: firstNonEmpty(source.DNS.RRName, source.HTTP.Hostname, source.TLS.SNI)}
	event.SecurityResult.Action = strings.ToLower(source.Alert.Action)
	event.Severity = suricataSeverity(source.Alert.Severity)
	event.Confidence = 90
	event.Metadata = map[string]interface{}{
		"event_type": source.EventType, "flow_id": source.FlowID, "protocol": source.Proto,
		"application_protocol": source.AppProto, "alert_category": source.Alert.Category,
		"dns_rrtype": source.DNS.RRType, "http_url": source.HTTP.URL, "http_status": source.HTTP.Status,
	}
	return event, nil
}

func suricataSeverity(value int) int {
	switch value {
	case 1:
		return 90
	case 2:
		return 70
	case 3:
		return 45
	default:
		return 20
	}
}

type ZeekJSON struct{}

type zeekEvent struct {
	Timestamp float64 `json:"ts"`
	UID       string  `json:"uid"`
	Path      string  `json:"_path"`
	SrcIP     string  `json:"id.orig_h"`
	SrcPort   int     `json:"id.orig_p"`
	DstIP     string  `json:"id.resp_h"`
	DstPort   int     `json:"id.resp_p"`
	Proto     string  `json:"proto"`
	Service   string  `json:"service"`
	Query     string  `json:"query"`
	QType     string  `json:"qtype_name"`
	RCode     string  `json:"rcode_name"`
	Host      string  `json:"host"`
	URI       string  `json:"uri"`
	Method    string  `json:"method"`
	Status    int     `json:"status_code"`
	Note      string  `json:"note"`
	Message   string  `json:"msg"`
	Username  string  `json:"username"`
}

func (ZeekJSON) Parse(_ context.Context, envelope ingest.RawEnvelope) (core.CanonicalEvent, error) {
	var source zeekEvent
	if err := json.Unmarshal(envelope.PayloadBytes(), &source); err != nil {
		return core.CanonicalEvent{}, fmt.Errorf("%w: decode Zeek JSON: %v", ErrParse, err)
	}
	if source.Timestamp <= 0 || validIP(source.SrcIP) == "" && validIP(source.DstIP) == "" {
		return core.CanonicalEvent{}, fmt.Errorf("%w: Zeek ts and endpoint are required", ErrParse)
	}
	category, activity, classUID := "network_activity", "Zeek connection", 4001
	switch {
	case source.Query != "":
		category, activity, classUID = "dns_activity", "DNS query", 4003
	case source.Method != "" || source.Host != "":
		category, activity, classUID = "web_activity", firstNonEmpty(source.Method, "HTTP")+" request", 4002
	case source.Note != "":
		activity = source.Note
	}
	event := xdrEvent(envelope, "zeek-json", "Zeek", "Zeek", "network", category, activity, classUID)
	event.EventTime = time.Unix(int64(source.Timestamp), int64((source.Timestamp-float64(int64(source.Timestamp)))*float64(time.Second))).UTC()
	event.SrcEndpoint = core.EndpointRef{IP: validIP(source.SrcIP), Port: source.SrcPort}
	event.DstEndpoint = core.EndpointRef{IP: validIP(source.DstIP), Port: source.DstPort, Hostname: firstNonEmpty(source.Query, source.Host)}
	event.User.Name = source.Username
	event.Severity = 25
	if source.Note != "" {
		event.Severity, event.Confidence = 65, 85
	}
	event.Metadata = map[string]interface{}{
		"uid": source.UID, "log_path": source.Path, "protocol": source.Proto, "service": source.Service,
		"dns_qtype": source.QType, "dns_rcode": source.RCode, "http_uri": source.URI,
		"http_status": source.Status, "notice_message": source.Message,
	}
	return event, nil
}
