package parser

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/ingest"
)

const StudioCompilerVersion = "kcsp-parser-dsl/1.0.0"

var (
	formatPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{2,63}$`)
	kvPattern      = regexp.MustCompile(`([A-Za-z0-9_.@-]+)=("(?:\\.|[^"])*"|'[^']*'|[^\s]+)`)
	allowedTargets = map[string]bool{
		"category": true, "activity_name": true, "severity": true, "event_time": true,
		"source.vendor": true, "source.product": true, "source.type": true,
		"user.id": true, "user.name": true, "device.id": true, "device.hostname": true, "device.department": true,
		"process.name": true, "process.command_line": true, "src_endpoint.ip": true, "dst_endpoint.ip": true,
	}
)

type CompiledParser struct{ content core.ParserContent }

func Compile(content core.ParserContent) (*CompiledParser, error) {
	report := ValidateDefinition(content.Spec)
	if !report.Valid {
		return nil, fmt.Errorf("%w: %s", ErrInvalidDefinition, strings.Join(report.Errors, "; "))
	}
	content.Spec = NormalizeSpec(content.Spec)
	return &CompiledParser{content: content}, nil
}

func (p *CompiledParser) Parse(_ context.Context, envelope ingest.RawEnvelope) (core.CanonicalEvent, error) {
	values, err := sourceValues(p.content.Spec.InputKind, envelope.PayloadBytes())
	if err != nil {
		return core.CanonicalEvent{}, fmt.Errorf("%w: %v", ErrParse, err)
	}
	value := func(target string) string {
		if source := p.content.Spec.Mappings[target]; source != "" {
			if extracted := lookupSource(values, source); extracted != "" {
				return extracted
			}
		}
		return p.content.Spec.Defaults[target]
	}
	event := core.CanonicalEvent{
		ID: envelope.EventID, TenantID: envelope.TenantID, CollectorID: envelope.CollectorID,
		EventTime: envelope.EventTimestamp.UTC(), IngestTime: envelope.ReceivedAt.UTC(),
		Category: value("category"), ActivityName: value("activity_name"),
		Parser: core.ParserRef{ID: p.content.ParserID, Version: strconv.Itoa(p.content.Version)},
	}
	event.Schema.OCSFVersion = "1.4.0"
	event.Source.Vendor, event.Source.Product, event.Source.Type = value("source.vendor"), value("source.product"), value("source.type")
	event.User.ID, event.User.Name = value("user.id"), value("user.name")
	event.Device.ID, event.Device.Hostname, event.Device.Department = value("device.id"), value("device.hostname"), value("device.department")
	event.Process.Name, event.Process.CommandLine = value("process.name"), value("process.command_line")
	event.SrcEndpoint.IP, event.DstEndpoint.IP = value("src_endpoint.ip"), value("dst_endpoint.ip")
	if severity, parseErr := strconv.Atoi(value("severity")); parseErr == nil {
		event.Severity = boundedScore(severity)
	}
	if parsed := parseMappedTime(value("event_time")); !parsed.IsZero() {
		event.EventTime = parsed
	}
	event.Raw.Message = string(envelope.PayloadBytes())
	event.Raw.Hash = envelope.RawHash
	event.Raw.Reference = "clickhouse://raw/" + envelope.TenantID + "/" + envelope.EventID
	if strings.TrimSpace(event.Category) == "" || strings.TrimSpace(event.Source.Type) == "" {
		return core.CanonicalEvent{}, fmt.Errorf("%w: parser produced no category or source.type", ErrParse)
	}
	return event, nil
}

func ValidateDefinition(spec core.ParserSpec) core.ParserValidationReport {
	spec = NormalizeSpec(spec)
	report := core.ParserValidationReport{SpecHash: parserSpecHash(spec), MappedFields: len(spec.Mappings), Errors: []string{}, Warnings: []string{}, Compiler: StudioCompilerVersion, OCSFCompatible: "1.4.0"}
	if !formatPattern.MatchString(spec.Format) {
		report.Errors = append(report.Errors, "format must match [a-z0-9][a-z0-9._-]{2,63}")
	}
	if IsBuiltInFormat(spec.Format) {
		report.Errors = append(report.Errors, "built-in formats cannot be overridden")
	}
	if spec.InputKind != "JSON" && spec.InputKind != "KV" {
		report.Errors = append(report.Errors, "input_kind must be JSON or KV")
	}
	for target, source := range spec.Mappings {
		if !allowedTargets[target] {
			report.Errors = append(report.Errors, "unsupported OCSF target: "+target)
		}
		if strings.TrimSpace(source) == "" {
			report.Errors = append(report.Errors, "source path is empty for "+target)
		}
	}
	for target := range spec.Defaults {
		if !allowedTargets[target] {
			report.Errors = append(report.Errors, "unsupported default target: "+target)
		}
	}
	for _, required := range []string{"category", "source.type"} {
		if spec.Mappings[required] == "" && spec.Defaults[required] == "" {
			report.Errors = append(report.Errors, required+" must have a mapping or default")
		}
	}
	if len(spec.Mappings) == 0 {
		report.Warnings = append(report.Warnings, "parser has no extracted fields and relies only on defaults")
	}
	if len(spec.Tests) == 0 {
		report.Warnings = append(report.Warnings, "no regression samples are attached")
	}
	report.Valid = len(report.Errors) == 0
	return report
}

func ValidateContent(content core.ParserContent) core.ParserValidationReport {
	report := ValidateDefinition(content.Spec)
	report.TestsTotal = len(content.Spec.Tests)
	compiled, err := Compile(content)
	if err != nil {
		report.Valid = false
		return report
	}
	for index, test := range content.Spec.Tests {
		name := strings.TrimSpace(test.Name)
		if name == "" {
			name = fmt.Sprintf("sample-%d", index+1)
		}
		result := core.ParserTestResult{Name: name, Passed: true, Errors: []string{}}
		envelope := ingest.RawEnvelope{TenantID: "parser-validation", CollectorID: "parser-studio", EventID: fmt.Sprintf("parser-test-%d", index+1), Format: content.Spec.Format, RawPayload: []byte(test.Payload), EventTimestamp: time.Now().UTC(), ReceivedAt: time.Now().UTC(), RawHash: "sha256:validation"}
		event, parseErr := compiled.Parse(context.Background(), envelope)
		if parseErr != nil {
			result.Passed = false
			result.Errors = append(result.Errors, parseErr.Error())
		} else {
			result.EventID = event.ID
			for field, expected := range test.Expected {
				actual, supported := EventField(event, field)
				if !supported {
					result.Passed = false
					result.Errors = append(result.Errors, "unsupported assertion field: "+field)
				} else if actual != expected {
					result.Passed = false
					result.Errors = append(result.Errors, fmt.Sprintf("%s: got %q, want %q", field, actual, expected))
				}
			}
		}
		if result.Passed {
			report.TestsPassed++
		} else {
			report.Errors = append(report.Errors, "sample failed: "+name)
		}
		report.TestResults = append(report.TestResults, result)
	}
	report.Valid = len(report.Errors) == 0
	report.ValidatedAt = time.Now().UTC()
	return report
}

func NormalizeSpec(spec core.ParserSpec) core.ParserSpec {
	spec.Format = strings.ToLower(strings.TrimSpace(spec.Format))
	spec.InputKind = strings.ToUpper(strings.TrimSpace(spec.InputKind))
	spec.Mappings = cleanParserMap(spec.Mappings)
	spec.Defaults = cleanParserMap(spec.Defaults)
	if spec.Tests == nil {
		spec.Tests = []core.ParserTestCase{}
	}
	for index := range spec.Tests {
		spec.Tests[index].Name = strings.TrimSpace(spec.Tests[index].Name)
		if spec.Tests[index].Expected == nil {
			spec.Tests[index].Expected = map[string]string{}
		}
	}
	return spec
}

func EventField(event core.CanonicalEvent, field string) (string, bool) {
	switch field {
	case "category":
		return event.Category, true
	case "activity_name":
		return event.ActivityName, true
	case "severity":
		return strconv.Itoa(event.Severity), true
	case "source.vendor":
		return event.Source.Vendor, true
	case "source.product":
		return event.Source.Product, true
	case "source.type":
		return event.Source.Type, true
	case "user.id":
		return event.User.ID, true
	case "user.name":
		return event.User.Name, true
	case "device.id":
		return event.Device.ID, true
	case "device.hostname":
		return event.Device.Hostname, true
	case "device.department":
		return event.Device.Department, true
	case "process.name":
		return event.Process.Name, true
	case "process.command_line":
		return event.Process.CommandLine, true
	case "src_endpoint.ip":
		return event.SrcEndpoint.IP, true
	case "dst_endpoint.ip":
		return event.DstEndpoint.IP, true
	default:
		return "", false
	}
}

func sourceValues(kind string, payload []byte) (map[string]interface{}, error) {
	if strings.EqualFold(kind, "JSON") {
		var value map[string]interface{}
		if err := json.Unmarshal(payload, &value); err != nil {
			return nil, fmt.Errorf("decode JSON sample: %w", err)
		}
		return value, nil
	}
	values := map[string]interface{}{}
	for _, match := range kvPattern.FindAllStringSubmatch(string(payload), -1) {
		value := strings.Trim(match[2], "\"'")
		values[match[1]] = strings.ReplaceAll(value, `\"`, `"`)
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("KV payload contains no key=value fields")
	}
	return values, nil
}

func lookupSource(values map[string]interface{}, path string) string {
	current := interface{}(values)
	for _, segment := range strings.Split(path, ".") {
		object, ok := current.(map[string]interface{})
		if !ok {
			return ""
		}
		current, ok = object[segment]
		if !ok {
			return ""
		}
	}
	switch value := current.(type) {
	case string:
		return strings.TrimSpace(value)
	case json.Number:
		return value.String()
	case float64:
		return strconv.FormatFloat(value, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(value)
	default:
		return ""
	}
}

func parseMappedTime(value string) time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05"} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed.UTC()
		}
	}
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		return time.Unix(seconds, 0).UTC()
	}
	return time.Time{}
}

func parserSpecHash(spec core.ParserSpec) string {
	payload, _ := json.Marshal(spec)
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func cleanParserMap(input map[string]string) map[string]string {
	result := make(map[string]string, len(input))
	for key, value := range input {
		if key, value = strings.TrimSpace(key), strings.TrimSpace(value); key != "" && value != "" {
			result[key] = value
		}
	}
	return result
}
