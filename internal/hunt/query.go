package hunt

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/kcsp/platform/internal/core"
)

var ErrInvalidQuery = errors.New("invalid hunt query")

const (
	DefaultLookback = 24 * time.Hour
	MaximumLookback = 31 * 24 * time.Hour
	DefaultLimit    = 100
	MaximumLimit    = 1000
)

type Cursor struct {
	EventTime time.Time `json:"event_time"`
	EventID   string    `json:"event_id"`
	QueryHash string    `json:"query_hash"`
}

type fieldDefinition struct {
	expression string
	kind       string
}

var fields = map[string]fieldDefinition{
	"event_id":                {"event_id", "string"},
	"category":                {"category", "string"},
	"severity":                {"severity", "number"},
	"source.vendor":           {"source_vendor", "string"},
	"source.product":          {"source_product", "string"},
	"source.type":             {"source_type", "string"},
	"user.name":               {"user_name", "string"},
	"device.hostname":         {"device_hostname", "string"},
	"src_endpoint.ip":         {"src_ip", "string"},
	"dst_endpoint.ip":         {"dst_ip", "string"},
	"activity_name":           {"JSONExtractString(payload, 'activity_name')", "string"},
	"collector_id":            {"JSONExtractString(payload, 'collector_id')", "string"},
	"process.name":            {"JSONExtractString(payload, 'process', 'name')", "string"},
	"process.command_line":    {"JSONExtractString(payload, 'process', 'command_line')", "string"},
	"security_result.action":  {"JSONExtractString(payload, 'security_result', 'action')", "string"},
	"security_result.outcome": {"JSONExtractString(payload, 'security_result', 'outcome')", "string"},
	"raw":                     {"payload", "text"},
}

var metadataFieldPattern = regexp.MustCompile(`^metadata(?:\.[A-Za-z0-9_-]{1,64}){1,8}$`)

func Normalize(request core.HuntRequest, now time.Time) (core.HuntRequest, error) {
	request.Cursor = strings.TrimSpace(request.Cursor)
	if len(request.Cursor) > 4096 {
		return core.HuntRequest{}, fmt.Errorf("%w: cursor is too large", ErrInvalidQuery)
	}
	if request.Start.IsZero() && request.End.IsZero() {
		if request.Cursor != "" {
			return core.HuntRequest{}, fmt.Errorf("%w: paginated requests must preserve start and end", ErrInvalidQuery)
		}
		lookback := DefaultLookback
		if request.LookbackSeconds > 0 {
			lookback = time.Duration(request.LookbackSeconds) * time.Second
		}
		request.End = now.UTC()
		request.Start = request.End.Add(-lookback)
	} else if request.Start.IsZero() || request.End.IsZero() {
		return core.HuntRequest{}, fmt.Errorf("%w: start and end must be provided together", ErrInvalidQuery)
	}
	request.Start = request.Start.UTC()
	request.End = request.End.UTC()
	window := request.End.Sub(request.Start)
	if window <= 0 || window > MaximumLookback {
		return core.HuntRequest{}, fmt.Errorf("%w: time range must be greater than zero and at most 31 days", ErrInvalidQuery)
	}
	if request.End.After(now.UTC().Add(5 * time.Minute)) {
		return core.HuntRequest{}, fmt.Errorf("%w: end cannot be more than five minutes in the future", ErrInvalidQuery)
	}
	request.LookbackSeconds = 0
	if request.Limit == 0 {
		request.Limit = DefaultLimit
	}
	if request.Limit < 1 || request.Limit > MaximumLimit {
		return core.HuntRequest{}, fmt.Errorf("%w: limit must be between 1 and 1000", ErrInvalidQuery)
	}
	count := 0
	if request.Expression != nil {
		if err := validateExpression(*request.Expression, 1, &count); err != nil {
			return core.HuntRequest{}, err
		}
	}
	return request, nil
}

func ValidateTemplate(request core.HuntRequest, now time.Time) (core.HuntRequest, error) {
	if strings.TrimSpace(request.Cursor) != "" {
		return core.HuntRequest{}, fmt.Errorf("%w: saved hunts cannot contain a cursor", ErrInvalidQuery)
	}
	if request.Start.IsZero() && request.End.IsZero() && request.LookbackSeconds == 0 {
		request.LookbackSeconds = int64(DefaultLookback / time.Second)
	}
	if request.LookbackSeconds > 0 {
		lookback := time.Duration(request.LookbackSeconds) * time.Second
		if lookback < time.Minute || lookback > MaximumLookback {
			return core.HuntRequest{}, fmt.Errorf("%w: saved lookback must be between one minute and 31 days", ErrInvalidQuery)
		}
		probe := request
		probe.Start = time.Time{}
		probe.End = time.Time{}
		if _, err := Normalize(probe, now); err != nil {
			return core.HuntRequest{}, err
		}
		request.Cursor = ""
		return request, nil
	}
	if _, err := Normalize(request, now); err != nil {
		return core.HuntRequest{}, err
	}
	return request, nil
}

func ResolveTemplate(request core.HuntRequest, now time.Time) (core.HuntRequest, error) {
	if request.LookbackSeconds > 0 {
		request.Start = time.Time{}
		request.End = time.Time{}
	}
	return Normalize(request, now)
}

func validateExpression(expression core.HuntExpression, depth int, count *int) error {
	if depth > 8 {
		return fmt.Errorf("%w: expression depth exceeds 8", ErrInvalidQuery)
	}
	branches := 0
	if len(expression.All) > 0 {
		branches++
	}
	if len(expression.Any) > 0 {
		branches++
	}
	if expression.Not != nil {
		branches++
	}
	if expression.Predicate != nil {
		branches++
	}
	if branches != 1 {
		return fmt.Errorf("%w: each expression must contain exactly one of all, any, not or predicate", ErrInvalidQuery)
	}
	children := expression.All
	if len(expression.Any) > 0 {
		children = expression.Any
	}
	if len(children) > 0 {
		if len(children) > 32 {
			return fmt.Errorf("%w: a boolean group supports at most 32 children", ErrInvalidQuery)
		}
		for _, child := range children {
			if err := validateExpression(child, depth+1, count); err != nil {
				return err
			}
		}
		return nil
	}
	if expression.Not != nil {
		return validateExpression(*expression.Not, depth+1, count)
	}
	*count++
	if *count > 64 {
		return fmt.Errorf("%w: query supports at most 64 predicates", ErrInvalidQuery)
	}
	return validatePredicate(*expression.Predicate)
}

func validatePredicate(predicate core.HuntPredicate) error {
	field, err := resolveField(predicate.Field)
	if err != nil {
		return err
	}
	comparator := strings.ToLower(strings.TrimSpace(predicate.Comparator))
	allowed := map[string]bool{"eq": true, "neq": true, "exists": true, "not_exists": true}
	if field.kind == "string" || field.kind == "text" {
		allowed["contains"] = true
		allowed["starts_with"] = true
		allowed["ends_with"] = true
		allowed["in"] = true
	}
	if field.kind == "number" {
		allowed["gt"] = true
		allowed["gte"] = true
		allowed["lt"] = true
		allowed["lte"] = true
		allowed["in"] = true
	}
	if !allowed[comparator] {
		return fmt.Errorf("%w: comparator %q is not supported for field %q", ErrInvalidQuery, comparator, predicate.Field)
	}
	if comparator == "exists" || comparator == "not_exists" {
		return nil
	}
	if comparator == "in" {
		if len(predicate.Values) == 0 || len(predicate.Values) > 100 {
			return fmt.Errorf("%w: in requires between 1 and 100 values", ErrInvalidQuery)
		}
		for _, value := range predicate.Values {
			if err := validateValue(field.kind, value); err != nil {
				return err
			}
		}
		return nil
	}
	return validateValue(field.kind, predicate.Value)
}

func validateValue(kind, value string) error {
	if value == "" || len(value) > 1024 {
		return fmt.Errorf("%w: predicate values must contain between 1 and 1024 characters", ErrInvalidQuery)
	}
	if kind == "number" {
		if _, err := strconv.ParseInt(value, 10, 64); err != nil {
			return fmt.Errorf("%w: numeric field requires an integer value", ErrInvalidQuery)
		}
	}
	return nil
}

func resolveField(name string) (fieldDefinition, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if field, ok := fields[name]; ok {
		return field, nil
	}
	if metadataFieldPattern.MatchString(name) {
		return fieldDefinition{expression: "JSON_VALUE(payload, '$." + name + "')", kind: "string"}, nil
	}
	return fieldDefinition{}, fmt.Errorf("%w: field %q is not searchable", ErrInvalidQuery, name)
}

func CompileExpression(expression *core.HuntExpression) (string, []interface{}, error) {
	if expression == nil {
		return "", nil, nil
	}
	return compileNode(*expression)
}

func compileNode(expression core.HuntExpression) (string, []interface{}, error) {
	if len(expression.All) > 0 || len(expression.Any) > 0 {
		children := expression.All
		operator := " AND "
		if len(expression.Any) > 0 {
			children = expression.Any
			operator = " OR "
		}
		parts := make([]string, 0, len(children))
		args := []interface{}{}
		for _, child := range children {
			part, childArgs, err := compileNode(child)
			if err != nil {
				return "", nil, err
			}
			parts = append(parts, "("+part+")")
			args = append(args, childArgs...)
		}
		return strings.Join(parts, operator), args, nil
	}
	if expression.Not != nil {
		part, args, err := compileNode(*expression.Not)
		return "NOT (" + part + ")", args, err
	}
	if expression.Predicate == nil {
		return "", nil, fmt.Errorf("%w: missing predicate", ErrInvalidQuery)
	}
	return compilePredicate(*expression.Predicate)
}

func compilePredicate(predicate core.HuntPredicate) (string, []interface{}, error) {
	field, err := resolveField(predicate.Field)
	if err != nil {
		return "", nil, err
	}
	comparator := strings.ToLower(strings.TrimSpace(predicate.Comparator))
	expression := field.expression
	if comparator == "exists" {
		return expression + " != ''", nil, nil
	}
	if comparator == "not_exists" {
		return expression + " = ''", nil, nil
	}
	values := predicate.Values
	if comparator != "in" {
		values = []string{predicate.Value}
	}
	args := make([]interface{}, 0, len(values))
	for _, value := range values {
		if field.kind == "number" {
			parsed, _ := strconv.ParseInt(value, 10, 64)
			args = append(args, parsed)
		} else {
			args = append(args, value)
		}
	}
	if comparator == "in" {
		placeholders := make([]string, len(args))
		for index := range placeholders {
			placeholders[index] = "?"
		}
		if field.kind == "number" {
			return expression + " IN (" + strings.Join(placeholders, ",") + ")", args, nil
		}
		return "lowerUTF8(" + expression + ") IN (" + strings.Join(lowerPlaceholders(placeholders), ",") + ")", args, nil
	}
	if field.kind == "number" {
		operators := map[string]string{"eq": "=", "neq": "!=", "gt": ">", "gte": ">=", "lt": "<", "lte": "<="}
		return expression + " " + operators[comparator] + " ?", args, nil
	}
	switch comparator {
	case "eq":
		return "lowerUTF8(" + expression + ") = lowerUTF8(?)", args, nil
	case "neq":
		return "lowerUTF8(" + expression + ") != lowerUTF8(?)", args, nil
	case "contains":
		return "positionCaseInsensitiveUTF8(" + expression + ", ?) > 0", args, nil
	case "starts_with":
		return "startsWith(lowerUTF8(" + expression + "), lowerUTF8(?))", args, nil
	case "ends_with":
		return "endsWith(lowerUTF8(" + expression + "), lowerUTF8(?))", args, nil
	default:
		return "", nil, fmt.Errorf("%w: unsupported comparator", ErrInvalidQuery)
	}
}

func lowerPlaceholders(placeholders []string) []string {
	result := make([]string, len(placeholders))
	for index := range placeholders {
		result[index] = "lowerUTF8(?)"
	}
	return result
}

func QueryHash(request core.HuntRequest) string {
	request.Cursor = ""
	payload, _ := json.Marshal(request)
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func EncodeCursor(cursor Cursor) string {
	payload, _ := json.Marshal(cursor)
	return base64.RawURLEncoding.EncodeToString(payload)
}

func DecodeCursor(value string) (Cursor, error) {
	if strings.TrimSpace(value) == "" {
		return Cursor{}, nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return Cursor{}, fmt.Errorf("%w: malformed cursor", ErrInvalidQuery)
	}
	var cursor Cursor
	if err := json.Unmarshal(payload, &cursor); err != nil || cursor.EventTime.IsZero() || cursor.EventID == "" || len(cursor.QueryHash) != 64 {
		return Cursor{}, fmt.Errorf("%w: malformed cursor", ErrInvalidQuery)
	}
	return cursor, nil
}
