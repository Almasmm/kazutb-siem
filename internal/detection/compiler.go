package detection

import (
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/kcsp/platform/internal/core"
	"gopkg.in/yaml.v3"
)

const CompilerVersion = "kcsp-sigma-ast/0.1.0"

var ErrInvalidRule = errors.New("invalid detection rule")

type sigmaDocument struct {
	Title          string                 `yaml:"title"`
	ID             string                 `yaml:"id"`
	Description    string                 `yaml:"description"`
	Status         string                 `yaml:"status"`
	Author         interface{}            `yaml:"author"`
	Level          string                 `yaml:"level"`
	Confidence     int                    `yaml:"confidence"`
	Tags           []string               `yaml:"tags"`
	FalsePositives []string               `yaml:"falsepositives"`
	LogSource      map[string]interface{} `yaml:"logsource"`
	Detection      map[string]interface{} `yaml:"detection"`
}

type CompiledRule struct {
	Rule       core.DetectionRule
	selections map[string]compiledSelection
	condition  conditionNode
}

type compiledSelection struct {
	alternatives []selectionAlternative
}

type selectionAlternative struct {
	fields []fieldPredicate
}

type fieldPredicate struct {
	field    string
	modifier string
	all      bool
	values   []string
}

func Compile(content core.DetectionContent) (*CompiledRule, error) {
	var document sigmaDocument
	decoder := yaml.NewDecoder(strings.NewReader(content.SigmaYAML))
	decoder.KnownFields(false)
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("%w: decode Sigma YAML: %v", ErrInvalidRule, err)
	}
	document.ID = strings.TrimSpace(document.ID)
	document.Title = strings.TrimSpace(document.Title)
	if document.ID == "" || document.Title == "" {
		return nil, fmt.Errorf("%w: Sigma id and title are required", ErrInvalidRule)
	}
	if content.RuleID != "" && content.RuleID != document.ID {
		return nil, fmt.Errorf("%w: route rule_id %q differs from Sigma id %q", ErrInvalidRule, content.RuleID, document.ID)
	}
	conditionText, ok := document.Detection["condition"].(string)
	if !ok || strings.TrimSpace(conditionText) == "" {
		return nil, fmt.Errorf("%w: detection.condition is required", ErrInvalidRule)
	}
	selections := map[string]compiledSelection{}
	for name, raw := range document.Detection {
		if name == "condition" || name == "timeframe" {
			continue
		}
		selection, err := compileSelection(name, raw)
		if err != nil {
			return nil, err
		}
		selections[name] = selection
	}
	if len(selections) == 0 {
		return nil, fmt.Errorf("%w: at least one detection selection is required", ErrInvalidRule)
	}
	expanded, err := expandQuantifiers(conditionText, selections)
	if err != nil {
		return nil, err
	}
	condition, err := parseCondition(expanded, selections)
	if err != nil {
		return nil, err
	}
	version := strings.TrimSpace(content.Version)
	if version == "" {
		return nil, fmt.Errorf("%w: rule version is required", ErrInvalidRule)
	}
	confidence := document.Confidence
	if confidence <= 0 || confidence > 100 {
		confidence = 70
	}
	rule := core.DetectionRule{
		ID: document.ID, Title: document.Title, Description: strings.TrimSpace(document.Description),
		Version: version, Severity: sigmaSeverity(document.Level), Confidence: confidence,
		MITRE: sigmaTechniques(document.Tags), RequiredDataSources: sigmaDataSources(document.LogSource),
		KnownFalsePositives: append([]string(nil), document.FalsePositives...), Owner: sigmaAuthor(document.Author),
		State: content.State, UpdatedAt: content.UpdatedAt,
	}
	return &CompiledRule{Rule: rule, selections: selections, condition: condition}, nil
}

func (rule *CompiledRule) Evaluate(event core.CanonicalEvent) (bool, []string) {
	results := make(map[string]bool, len(rule.selections))
	matchedFields := map[string]bool{}
	for name, selection := range rule.selections {
		matched, fields := selection.evaluate(event)
		results[name] = matched
		if matched {
			for _, field := range fields {
				matchedFields[field] = true
			}
		}
	}
	if !rule.condition.evaluate(results) {
		return false, nil
	}
	fields := make([]string, 0, len(matchedFields))
	for field := range matchedFields {
		fields = append(fields, field)
	}
	sort.Strings(fields)
	return true, fields
}

func compileSelection(name string, raw interface{}) (compiledSelection, error) {
	selection := compiledSelection{}
	switch value := raw.(type) {
	case map[string]interface{}:
		alternative, err := compileAlternative(name, value)
		if err != nil {
			return compiledSelection{}, err
		}
		selection.alternatives = []selectionAlternative{alternative}
	case []interface{}:
		for _, item := range value {
			mapping, ok := item.(map[string]interface{})
			if !ok {
				return compiledSelection{}, fmt.Errorf("%w: selection %q alternatives must be mappings", ErrInvalidRule, name)
			}
			alternative, err := compileAlternative(name, mapping)
			if err != nil {
				return compiledSelection{}, err
			}
			selection.alternatives = append(selection.alternatives, alternative)
		}
	default:
		return compiledSelection{}, fmt.Errorf("%w: selection %q must be a mapping or list of mappings", ErrInvalidRule, name)
	}
	if len(selection.alternatives) == 0 {
		return compiledSelection{}, fmt.Errorf("%w: selection %q is empty", ErrInvalidRule, name)
	}
	return selection, nil
}

func compileAlternative(selectionName string, mapping map[string]interface{}) (selectionAlternative, error) {
	alternative := selectionAlternative{}
	for expression, raw := range mapping {
		parts := strings.Split(expression, "|")
		field := strings.TrimSpace(parts[0])
		if field == "" {
			return selectionAlternative{}, fmt.Errorf("%w: selection %q has an empty field", ErrInvalidRule, selectionName)
		}
		predicate := fieldPredicate{field: field, modifier: "equals"}
		for _, modifier := range parts[1:] {
			switch strings.ToLower(strings.TrimSpace(modifier)) {
			case "contains", "startswith", "endswith":
				predicate.modifier = strings.ToLower(strings.TrimSpace(modifier))
			case "all":
				predicate.all = true
			case "windash", "cased":
				return selectionAlternative{}, fmt.Errorf("%w: modifier %q is not supported by compiler %s", ErrInvalidRule, modifier, CompilerVersion)
			default:
				return selectionAlternative{}, fmt.Errorf("%w: unknown modifier %q", ErrInvalidRule, modifier)
			}
		}
		values, err := scalarValues(raw)
		if err != nil {
			return selectionAlternative{}, fmt.Errorf("%w: selection %q field %q: %v", ErrInvalidRule, selectionName, field, err)
		}
		predicate.values = values
		alternative.fields = append(alternative.fields, predicate)
	}
	if len(alternative.fields) == 0 {
		return selectionAlternative{}, fmt.Errorf("%w: selection %q mapping is empty", ErrInvalidRule, selectionName)
	}
	sort.Slice(alternative.fields, func(i, j int) bool { return alternative.fields[i].field < alternative.fields[j].field })
	return alternative, nil
}

func scalarValues(raw interface{}) ([]string, error) {
	items := []interface{}{raw}
	if list, ok := raw.([]interface{}); ok {
		items = list
	}
	if len(items) == 0 {
		return nil, errors.New("value list is empty")
	}
	values := make([]string, 0, len(items))
	for _, item := range items {
		switch value := item.(type) {
		case string:
			values = append(values, value)
		case bool:
			values = append(values, strconv.FormatBool(value))
		case int, int64, uint64, float64:
			values = append(values, fmt.Sprint(value))
		default:
			return nil, fmt.Errorf("value type %T is not scalar", item)
		}
	}
	return values, nil
}

func (selection compiledSelection) evaluate(event core.CanonicalEvent) (bool, []string) {
	for _, alternative := range selection.alternatives {
		fields := []string{}
		matched := true
		for _, predicate := range alternative.fields {
			if !predicate.evaluate(event) {
				matched = false
				break
			}
			fields = append(fields, predicate.field)
		}
		if matched {
			return true, fields
		}
	}
	return false, nil
}

func (predicate fieldPredicate) evaluate(event core.CanonicalEvent) bool {
	actualValues := eventFieldValues(event, predicate.field)
	if len(actualValues) == 0 {
		return false
	}
	matchExpected := func(expected string) bool {
		for _, actual := range actualValues {
			if matchValue(actual, expected, predicate.modifier) {
				return true
			}
		}
		return false
	}
	if predicate.all {
		for _, expected := range predicate.values {
			if !matchExpected(expected) {
				return false
			}
		}
		return true
	}
	for _, expected := range predicate.values {
		if matchExpected(expected) {
			return true
		}
	}
	return false
}

func matchValue(actual, expected, modifier string) bool {
	actual = strings.ToLower(actual)
	expected = strings.ToLower(expected)
	switch modifier {
	case "contains":
		return strings.Contains(actual, expected)
	case "startswith":
		return strings.HasPrefix(actual, expected)
	case "endswith":
		return strings.HasSuffix(actual, expected)
	default:
		if strings.ContainsAny(expected, "*?") {
			matched, _ := path.Match(strings.ReplaceAll(expected, `\`, "/"), strings.ReplaceAll(actual, `\`, "/"))
			return matched
		}
		return actual == expected
	}
}

func eventFieldValues(event core.CanonicalEvent, field string) []string {
	var value interface{}
	switch strings.ToLower(field) {
	case "event_id":
		value = event.ID
	case "category":
		value = event.Category
	case "activity_name", "activity":
		value = event.ActivityName
	case "source.vendor":
		value = event.Source.Vendor
	case "source.product":
		value = event.Source.Product
	case "source.type":
		value = event.Source.Type
	case "user.name":
		value = event.User.Name
	case "user.is_privileged":
		value = event.User.IsPrivileged
	case "device.hostname":
		value = event.Device.Hostname
	case "device.ip":
		value = event.Device.IP
	case "device.criticality":
		value = event.Device.Criticality
	case "src_endpoint.ip":
		value = event.SrcEndpoint.IP
	case "src_endpoint.port":
		value = event.SrcEndpoint.Port
	case "dst_endpoint.ip":
		value = event.DstEndpoint.IP
	case "dst_endpoint.port":
		value = event.DstEndpoint.Port
	case "process.name":
		value = event.Process.Name
	case "process.command_line":
		value = event.Process.CommandLine
	case "process.parent_name":
		value = event.Process.ParentName
	case "security_result.action":
		value = event.SecurityResult.Action
	case "security_result.outcome":
		value = event.SecurityResult.Outcome
	default:
		value = nestedValue(event.Metadata, strings.TrimPrefix(field, "metadata."))
	}
	if value == nil {
		return nil
	}
	switch typed := value.(type) {
	case []string:
		return typed
	case []interface{}:
		values := make([]string, 0, len(typed))
		for _, item := range typed {
			values = append(values, fmt.Sprint(item))
		}
		return values
	case string:
		if typed == "" {
			return nil
		}
		return []string{typed}
	default:
		return []string{fmt.Sprint(typed)}
	}
}

func nestedValue(metadata map[string]interface{}, pathValue string) interface{} {
	if metadata == nil || pathValue == "" {
		return nil
	}
	var current interface{} = metadata
	for _, segment := range strings.Split(pathValue, ".") {
		mapping, ok := current.(map[string]interface{})
		if !ok {
			return nil
		}
		current, ok = mapping[segment]
		if !ok {
			return nil
		}
	}
	return current
}

func sigmaSeverity(level string) core.Severity {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "critical":
		return core.SeverityCritical
	case "high":
		return core.SeverityHigh
	case "medium":
		return core.SeverityMedium
	case "low":
		return core.SeverityLow
	default:
		return core.SeverityInformational
	}
}

func sigmaTechniques(tags []string) []string {
	result := []string{}
	seen := map[string]bool{}
	for _, tag := range tags {
		value := strings.ToUpper(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(tag)), "attack."))
		if strings.HasPrefix(value, "T") && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}

func sigmaDataSources(logSource map[string]interface{}) []string {
	parts := []string{}
	for _, key := range []string{"category", "product", "service"} {
		if value := strings.TrimSpace(fmt.Sprint(logSource[key])); value != "" && value != "<nil>" {
			parts = append(parts, value)
		}
	}
	if len(parts) == 0 {
		return nil
	}
	return []string{strings.Join(parts, "/")}
}

func sigmaAuthor(value interface{}) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case []interface{}:
		parts := make([]string, 0, len(typed))
		for _, item := range typed {
			parts = append(parts, fmt.Sprint(item))
		}
		return strings.Join(parts, ", ")
	default:
		return "KCSP Detection Engineering"
	}
}

var quantifierPattern = regexp.MustCompile(`(?i)\b(1|all)\s+of\s+(them|[a-zA-Z0-9_.*-]+)`)

func expandQuantifiers(condition string, selections map[string]compiledSelection) (string, error) {
	names := make([]string, 0, len(selections))
	for name := range selections {
		names = append(names, name)
	}
	sort.Strings(names)
	var expansionError error
	expanded := quantifierPattern.ReplaceAllStringFunc(condition, func(fragment string) string {
		match := quantifierPattern.FindStringSubmatch(fragment)
		selected := []string{}
		if strings.EqualFold(match[2], "them") {
			selected = append(selected, names...)
		} else {
			pattern := strings.ToLower(match[2])
			for _, name := range names {
				if ok, _ := path.Match(pattern, strings.ToLower(name)); ok {
					selected = append(selected, name)
				}
			}
		}
		if len(selected) == 0 {
			expansionError = fmt.Errorf("%w: quantifier %q matches no selections", ErrInvalidRule, fragment)
			return fragment
		}
		operator := " or "
		if strings.EqualFold(match[1], "all") {
			operator = " and "
		}
		return "(" + strings.Join(selected, operator) + ")"
	})
	return expanded, expansionError
}

type conditionNode interface{ evaluate(map[string]bool) bool }
type selectionNode string

func (n selectionNode) evaluate(values map[string]bool) bool { return values[string(n)] }

type notNode struct{ child conditionNode }

func (n notNode) evaluate(values map[string]bool) bool { return !n.child.evaluate(values) }

type binaryNode struct {
	operator    string
	left, right conditionNode
}

func (n binaryNode) evaluate(values map[string]bool) bool {
	if n.operator == "and" {
		return n.left.evaluate(values) && n.right.evaluate(values)
	}
	return n.left.evaluate(values) || n.right.evaluate(values)
}

type conditionParser struct {
	tokens     []string
	position   int
	selections map[string]compiledSelection
}

func parseCondition(input string, selections map[string]compiledSelection) (conditionNode, error) {
	parser := &conditionParser{tokens: tokenizeCondition(input), selections: selections}
	if len(parser.tokens) == 0 {
		return nil, fmt.Errorf("%w: empty condition", ErrInvalidRule)
	}
	node, err := parser.parseOr()
	if err != nil {
		return nil, err
	}
	if parser.position != len(parser.tokens) {
		return nil, fmt.Errorf("%w: unexpected condition token %q", ErrInvalidRule, parser.tokens[parser.position])
	}
	return node, nil
}

func tokenizeCondition(value string) []string {
	value = strings.NewReplacer("(", " ( ", ")", " ) ").Replace(value)
	return strings.Fields(value)
}

func (p *conditionParser) parseOr() (conditionNode, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.peek("or") {
		p.position++
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = binaryNode{operator: "or", left: left, right: right}
	}
	return left, nil
}
func (p *conditionParser) parseAnd() (conditionNode, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for p.peek("and") {
		p.position++
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		left = binaryNode{operator: "and", left: left, right: right}
	}
	return left, nil
}
func (p *conditionParser) parseUnary() (conditionNode, error) {
	if p.peek("not") {
		p.position++
		child, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return notNode{child: child}, nil
	}
	if p.peek("(") {
		p.position++
		node, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if !p.peek(")") {
			return nil, fmt.Errorf("%w: missing closing parenthesis", ErrInvalidRule)
		}
		p.position++
		return node, nil
	}
	if p.position >= len(p.tokens) {
		return nil, fmt.Errorf("%w: unexpected end of condition", ErrInvalidRule)
	}
	name := p.tokens[p.position]
	p.position++
	if _, ok := p.selections[name]; !ok {
		return nil, fmt.Errorf("%w: condition references unknown selection %q", ErrInvalidRule, name)
	}
	return selectionNode(name), nil
}
func (p *conditionParser) peek(value string) bool {
	return p.position < len(p.tokens) && strings.EqualFold(p.tokens[p.position], value)
}

func MarshalASTSummary(rule *CompiledRule) []byte {
	summary := map[string]interface{}{"compiler": CompilerVersion, "rule": rule.Rule, "selections": len(rule.selections)}
	body, _ := json.Marshal(summary)
	return body
}
