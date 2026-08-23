package threatintel

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- RFC 4122 UUIDv5 interoperability requires SHA-1; it is not a security digest.
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/kcsp/platform/internal/core"
)

const MaximumSTIXObjects = 2000

type STIXImportRejection struct {
	Index    int    `json:"index"`
	ObjectID string `json:"object_id,omitempty"`
	Reason   string `json:"reason"`
}

type STIXImportReport struct {
	BundleID      string                `json:"bundle_id"`
	Objects       int                   `json:"objects"`
	Imported      int                   `json:"imported"`
	Created       int                   `json:"created"`
	Updated       int                   `json:"updated"`
	Revoked       int                   `json:"revoked"`
	Skipped       int                   `json:"skipped"`
	RejectedCount int                   `json:"rejected_count"`
	Rejected      []STIXImportRejection `json:"rejected"`
}

type STIXBundle struct {
	Type    string                `json:"type"`
	ID      string                `json:"id"`
	Objects []STIXIndicatorObject `json:"objects"`
}

type STIXIndicatorObject struct {
	Type             string     `json:"type"`
	SpecVersion      string     `json:"spec_version"`
	ID               string     `json:"id"`
	Created          time.Time  `json:"created"`
	Modified         time.Time  `json:"modified"`
	Name             string     `json:"name"`
	Description      string     `json:"description,omitempty"`
	IndicatorTypes   []string   `json:"indicator_types"`
	Pattern          string     `json:"pattern"`
	PatternType      string     `json:"pattern_type"`
	PatternVersion   string     `json:"pattern_version"`
	ValidFrom        time.Time  `json:"valid_from"`
	ValidUntil       *time.Time `json:"valid_until,omitempty"`
	Confidence       int        `json:"confidence"`
	Labels           []string   `json:"labels,omitempty"`
	Revoked          bool       `json:"revoked,omitempty"`
	XKCSPSource      string     `json:"x_kcsp_source,omitempty"`
	XKCSPFeedID      string     `json:"x_kcsp_feed_id,omitempty"`
	XKCSPIndicatorID string     `json:"x_kcsp_indicator_id,omitempty"`
}

type parsedSTIXIndicator struct {
	ObjectID string
	Draft    IndicatorDraft
	Revoked  bool
}

var (
	stixPatternExpression = regexp.MustCompile(`^\[\s*([A-Za-z0-9-]+):([A-Za-z0-9_.-]+|hashes\.'[A-Za-z0-9-]+')\s*=\s*'((?:\\.|[^'])*)'\s*\]$`)
	stixIndicatorID       = regexp.MustCompile(`^indicator--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)
)

func (s *Service) ImportSTIX(ctx context.Context, tenantID, actor, feedID string, payload []byte) (STIXImportReport, error) {
	feed, err := s.store.GetThreatIntelFeed(ctx, tenantID, strings.TrimSpace(feedID))
	if err != nil {
		return STIXImportReport{}, err
	}
	parsed, report, err := ParseSTIXBundle(payload)
	if err != nil {
		return report, err
	}
	for _, item := range parsed {
		indicator, created, upsertErr := s.upsertIndicatorForFeed(ctx, tenantID, actor, feed, item.Draft)
		if upsertErr != nil {
			if errors.Is(upsertErr, ErrInvalidIndicator) {
				report.Rejected = append(report.Rejected, STIXImportRejection{ObjectID: item.ObjectID, Reason: upsertErr.Error()})
				report.RejectedCount++
				continue
			}
			return report, upsertErr
		}
		report.Imported++
		if created {
			report.Created++
		} else {
			report.Updated++
		}
		if item.Revoked && indicator.State != core.ThreatIntelStateRevoked {
			if _, stateErr := s.SetIndicatorState(ctx, tenantID, indicator.ID, actor, core.ThreatIntelStateRevoked, indicator.Version); stateErr != nil {
				return report, stateErr
			}
			report.Revoked++
		}
	}
	return report, nil
}

func (s *Service) ExportSTIX(ctx context.Context, tenantID string, filter core.ThreatIndicatorFilter) (STIXBundle, error) {
	if filter.Limit <= 0 {
		filter.Limit = 500
	}
	indicators, err := s.Indicators(ctx, tenantID, filter)
	if err != nil {
		return STIXBundle{}, err
	}
	return BuildSTIXBundle(tenantID, indicators), nil
}

func ParseSTIXBundle(payload []byte) ([]parsedSTIXIndicator, STIXImportReport, error) {
	var envelope struct {
		Type    string            `json:"type"`
		ID      string            `json:"id"`
		Objects []json.RawMessage `json:"objects"`
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	if err := decoder.Decode(&envelope); err != nil {
		return nil, STIXImportReport{}, fmt.Errorf("%w: decode STIX bundle: %v", ErrInvalidIndicator, err)
	}
	if envelope.Type != "bundle" || !strings.HasPrefix(envelope.ID, "bundle--") {
		return nil, STIXImportReport{}, fmt.Errorf("%w: STIX payload must be a bundle with a bundle-- identifier", ErrInvalidIndicator)
	}
	if len(envelope.Objects) > MaximumSTIXObjects {
		return nil, STIXImportReport{}, fmt.Errorf("%w: STIX bundle exceeds %d objects", ErrInvalidIndicator, MaximumSTIXObjects)
	}
	report := STIXImportReport{BundleID: envelope.ID, Objects: len(envelope.Objects), Rejected: []STIXImportRejection{}}
	parsed := make([]parsedSTIXIndicator, 0, len(envelope.Objects))
	for index, raw := range envelope.Objects {
		var header struct {
			Type string `json:"type"`
			ID   string `json:"id"`
		}
		if err := json.Unmarshal(raw, &header); err != nil {
			report.Rejected = append(report.Rejected, STIXImportRejection{Index: index, Reason: "object is not valid JSON"})
			continue
		}
		if header.Type != "indicator" {
			report.Skipped++
			continue
		}
		item, err := parseSTIXIndicator(raw)
		if err != nil {
			report.Rejected = append(report.Rejected, STIXImportRejection{Index: index, ObjectID: header.ID, Reason: err.Error()})
			continue
		}
		parsed = append(parsed, item)
	}
	report.RejectedCount = len(report.Rejected)
	return parsed, report, nil
}

func parseSTIXIndicator(raw []byte) (parsedSTIXIndicator, error) {
	var object struct {
		Type           string     `json:"type"`
		SpecVersion    string     `json:"spec_version"`
		ID             string     `json:"id"`
		Created        *time.Time `json:"created"`
		Modified       *time.Time `json:"modified"`
		Name           string     `json:"name"`
		Description    string     `json:"description"`
		IndicatorTypes []string   `json:"indicator_types"`
		Pattern        string     `json:"pattern"`
		PatternType    string     `json:"pattern_type"`
		PatternVersion string     `json:"pattern_version"`
		ValidFrom      *time.Time `json:"valid_from"`
		ValidUntil     *time.Time `json:"valid_until"`
		Confidence     *int       `json:"confidence"`
		Labels         []string   `json:"labels"`
		Revoked        bool       `json:"revoked"`
	}
	if err := json.Unmarshal(raw, &object); err != nil {
		return parsedSTIXIndicator{}, fmt.Errorf("decode STIX indicator: %w", err)
	}
	if object.SpecVersion != "2.1" || object.PatternType != "stix" ||
		(object.PatternVersion != "" && object.PatternVersion != "2.1") {
		return parsedSTIXIndicator{}, errors.New("only STIX 2.1 indicator patterns are supported")
	}
	if !stixIndicatorID.MatchString(object.ID) || object.ValidFrom == nil {
		return parsedSTIXIndicator{}, errors.New("indicator requires a valid indicator-- UUID and valid_from")
	}
	indicatorType, value, err := ParseSTIXPattern(object.Pattern)
	if err != nil {
		return parsedSTIXIndicator{}, err
	}
	firstSeen := object.ValidFrom.UTC()
	if object.Created != nil && object.Created.Before(firstSeen) {
		firstSeen = object.Created.UTC()
	}
	lastSeen := firstSeen
	if object.Modified != nil && object.Modified.After(lastSeen) {
		lastSeen = object.Modified.UTC()
	}
	reputation := "UNKNOWN"
	for _, indicatorKind := range object.IndicatorTypes {
		switch strings.ToLower(indicatorKind) {
		case "malicious-activity":
			reputation = "MALICIOUS"
		case "anomalous-activity":
			if reputation != "MALICIOUS" {
				reputation = "SUSPICIOUS"
			}
		case "benign":
			if reputation == "UNKNOWN" {
				reputation = "TRUSTED"
			}
		}
	}
	tags := append(append([]string{}, object.Labels...), object.IndicatorTypes...)
	return parsedSTIXIndicator{
		ObjectID: object.ID, Revoked: object.Revoked,
		Draft: IndicatorDraft{
			Type: indicatorType, Value: value, Confidence: object.Confidence, Reputation: reputation,
			FirstSeen: firstSeen, LastSeen: lastSeen, ValidFrom: object.ValidFrom.UTC(),
			ValidUntil: object.ValidUntil, Tags: tags, Description: object.Description, ExternalID: object.ID,
		},
	}, nil
}

func ParseSTIXPattern(pattern string) (core.ThreatIndicatorType, string, error) {
	parts := stixPatternExpression.FindStringSubmatch(strings.TrimSpace(pattern))
	if len(parts) != 4 {
		return "", "", errors.New("unsupported STIX pattern; one equality comparison is required")
	}
	value, err := unescapeSTIXString(parts[3])
	if err != nil {
		return "", "", err
	}
	key := strings.ToLower(parts[1] + ":" + parts[2])
	var indicatorType core.ThreatIndicatorType
	switch key {
	case "ipv4-addr:value":
		indicatorType = core.ThreatIndicatorIPv4
	case "ipv6-addr:value":
		indicatorType = core.ThreatIndicatorIPv6
	case "domain-name:value":
		indicatorType = core.ThreatIndicatorDomain
	case "url:value":
		indicatorType = core.ThreatIndicatorURL
	case "email-addr:value":
		indicatorType = core.ThreatIndicatorEmail
	case "file:hashes.'md5'", "file:hashes.'sha-1'", "file:hashes.'sha-256'", "file:hashes.'sha-512'":
		indicatorType = core.ThreatIndicatorHash
	case "x509-certificate:hashes.'sha-1'", "x509-certificate:hashes.'sha-256'", "x509-certificate:hashes.'sha-512'":
		indicatorType = core.ThreatIndicatorCertificateFingerprint
	default:
		return "", "", fmt.Errorf("unsupported STIX observable path %s", key)
	}
	if _, err := NormalizeValue(indicatorType, value); err != nil {
		return "", "", err
	}
	return indicatorType, value, nil
}

func BuildSTIXBundle(tenantID string, indicators []core.ThreatIndicator) STIXBundle {
	objects := make([]STIXIndicatorObject, 0, len(indicators))
	for _, indicator := range indicators {
		objects = append(objects, STIXIndicatorObject{
			Type: "indicator", SpecVersion: "2.1", ID: exportSTIXIndicatorID(tenantID, indicator),
			Created: indicator.CreatedAt.UTC(), Modified: indicator.UpdatedAt.UTC(),
			Name:        "KCSP " + strings.ToLower(string(indicator.Type)) + " indicator",
			Description: indicator.Description, IndicatorTypes: []string{stixIndicatorKind(indicator.Reputation)},
			Pattern: STIXPattern(indicator), PatternType: "stix", PatternVersion: "2.1",
			ValidFrom: indicator.ValidFrom.UTC(), ValidUntil: indicator.ValidUntil, Confidence: indicator.Confidence,
			Labels: append([]string(nil), indicator.Tags...), Revoked: indicator.State == core.ThreatIntelStateRevoked,
			XKCSPSource: indicator.Source, XKCSPFeedID: indicator.FeedID, XKCSPIndicatorID: indicator.ID,
		})
	}
	return STIXBundle{Type: "bundle", ID: "bundle--" + randomUUID(), Objects: objects}
}

func STIXPattern(indicator core.ThreatIndicator) string {
	path := ""
	switch indicator.Type {
	case core.ThreatIndicatorIPv4:
		path = "ipv4-addr:value"
	case core.ThreatIndicatorIPv6:
		path = "ipv6-addr:value"
	case core.ThreatIndicatorDomain:
		path = "domain-name:value"
	case core.ThreatIndicatorURL:
		path = "url:value"
	case core.ThreatIndicatorEmail:
		path = "email-addr:value"
	case core.ThreatIndicatorCertificateFingerprint:
		path = "x509-certificate:hashes.'" + hashAlgorithm(indicator.NormalizedValue) + "'"
	default:
		path = "file:hashes.'" + hashAlgorithm(indicator.NormalizedValue) + "'"
	}
	value := strings.ReplaceAll(indicator.NormalizedValue, "\\", "\\\\")
	value = strings.ReplaceAll(value, "'", "\\'")
	return "[" + path + " = '" + value + "']"
}

func unescapeSTIXString(value string) (string, error) {
	var output strings.Builder
	escaped := false
	for _, character := range value {
		if escaped {
			if character != '\\' && character != '\'' {
				return "", errors.New("unsupported STIX string escape")
			}
			output.WriteRune(character)
			escaped = false
			continue
		}
		if character == '\\' {
			escaped = true
			continue
		}
		output.WriteRune(character)
	}
	if escaped {
		return "", errors.New("unterminated STIX string escape")
	}
	return output.String(), nil
}

func hashAlgorithm(value string) string {
	switch len(value) {
	case 32:
		return "MD5"
	case 40:
		return "SHA-1"
	case 128:
		return "SHA-512"
	default:
		return "SHA-256"
	}
}

func stixIndicatorKind(reputation string) string {
	switch reputation {
	case "MALICIOUS":
		return "malicious-activity"
	case "SUSPICIOUS":
		return "anomalous-activity"
	case "TRUSTED":
		return "benign"
	default:
		return "unknown"
	}
}

func exportSTIXIndicatorID(tenantID string, indicator core.ThreatIndicator) string {
	if stixIndicatorID.MatchString(indicator.ExternalID) {
		return indicator.ExternalID
	}
	return "indicator--" + deterministicUUID(tenantID+"|"+indicator.ID)
}

func deterministicUUID(value string) string {
	// #nosec G401 -- RFC 4122 UUIDv5 requires SHA-1 and this value is only a stable identifier.
	sum := sha1.Sum([]byte("kcsp-stix-2.1|" + value))
	bytes := append([]byte(nil), sum[:16]...)
	bytes[6] = (bytes[6] & 0x0f) | 0x50
	bytes[8] = (bytes[8] & 0x3f) | 0x80
	return formatUUID(bytes)
}

func randomUUID() string {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		seed := fmt.Sprintf("%s|%d", time.Now().UTC().Format(time.RFC3339Nano), uuidFallbackSequence.Add(1))
		sum := sha256.Sum256([]byte(seed))
		copy(value, sum[:16])
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	return formatUUID(value)
}

var uuidFallbackSequence atomic.Uint64

func formatUUID(value []byte) string {
	encoded := hex.EncodeToString(value)
	return encoded[0:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:32]
}
