package soar

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/kcsp/platform/internal/core"
)

var (
	ErrInvalidPlaybook         = errors.New("invalid SOAR playbook")
	ErrValidationFailed        = errors.New("SOAR playbook validation failed")
	ErrInvalidState            = errors.New("invalid SOAR lifecycle state")
	ErrInvalidExecution        = errors.New("invalid SOAR execution")
	ErrInvalidApprovalDecision = errors.New("invalid SOAR approval decision")
	ErrInvalidApprovalReason   = errors.New("invalid SOAR approval reason")
	ErrApprovalVersionConflict = errors.New("SOAR approval version conflict")
)

type ActionDescriptor struct {
	Type       string
	Level      int
	Reversible bool
}

type ActionCatalog map[string]ActionDescriptor

func DefaultActionCatalog() ActionCatalog {
	return ActionCatalog{
		"kcsp.enrich.threat_intel":      {Type: "kcsp.enrich.threat_intel", Level: 0},
		"kcsp.ticket.create":            {Type: "kcsp.ticket.create", Level: 1},
		"kcsp.ticket.update":            {Type: "kcsp.ticket.update", Level: 1},
		"kcsp.ticket.comment":           {Type: "kcsp.ticket.comment", Level: 1},
		"kcsp.ticket.close":             {Type: "kcsp.ticket.close", Level: 2},
		"kcsp.notification.send":        {Type: "kcsp.notification.send", Level: 2},
		"endpoint.isolate":              {Type: "endpoint.isolate", Level: 3, Reversible: true},
		"endpoint.release":              {Type: "endpoint.release", Level: 3},
		"identity.disable_account":      {Type: "identity.disable_account", Level: 4, Reversible: true},
		"identity.enable_account":       {Type: "identity.enable_account", Level: 4},
		"firewall.block_ip":             {Type: "firewall.block_ip", Level: 5, Reversible: true},
		"firewall.unblock_ip":           {Type: "firewall.unblock_ip", Level: 5},
		"threat_intel.indicator.submit": {Type: "threat_intel.indicator.submit", Level: 1},
		"destructive.erase_evidence":    {Type: "destructive.erase_evidence", Level: 6},
	}
}

type Validator struct {
	Actions ActionCatalog
	Now     func() time.Time
}

var nodeIDPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,63}$`)

func NewValidator(actions ActionCatalog) *Validator {
	if actions == nil {
		actions = DefaultActionCatalog()
	}
	return &Validator{Actions: actions, Now: func() time.Time { return time.Now().UTC() }}
}

func (v *Validator) Validate(spec core.SOARPlaybookSpec) core.SOARValidationReport {
	payload, _ := json.Marshal(spec)
	sum := sha256.Sum256(payload)
	report := core.SOARValidationReport{
		SpecHash: hex.EncodeToString(sum[:]), NodeCount: len(spec.Nodes),
		Issues: []core.SOARValidationIssue{}, ValidatedAt: v.Now(),
	}
	add := func(level, code, path, message string) {
		report.Issues = append(report.Issues, core.SOARValidationIssue{Level: level, Code: code, Path: path, Message: message})
	}
	if spec.SchemaVersion != "1.0" {
		add("ERROR", "schema_version", "schema_version", "schema_version must be 1.0")
	}
	switch strings.ToUpper(strings.TrimSpace(spec.Trigger.Type)) {
	case "MANUAL", "ALERT", "INCIDENT":
	default:
		add("ERROR", "trigger_type", "trigger.type", "trigger type must be MANUAL, ALERT, or INCIDENT")
	}
	if len(spec.Nodes) == 0 || len(spec.Nodes) > 100 {
		add("ERROR", "node_count", "nodes", "playbook must contain between 1 and 100 nodes")
	}
	nodes := make(map[string]core.SOARNode, len(spec.Nodes))
	for index, node := range spec.Nodes {
		path := fmt.Sprintf("nodes[%d]", index)
		if !nodeIDPattern.MatchString(node.ID) {
			add("ERROR", "node_id", path+".id", "node id must be a stable 1-64 character identifier")
			continue
		}
		if _, exists := nodes[node.ID]; exists {
			add("ERROR", "duplicate_node", path+".id", "node id must be unique")
			continue
		}
		nodes[node.ID] = node
		validateNode(v.Actions, node, path, add)
	}
	roots := 0
	for index, node := range spec.Nodes {
		if len(node.DependsOn) == 0 {
			roots++
		}
		seenDependency := map[string]bool{}
		for _, dependency := range node.DependsOn {
			path := fmt.Sprintf("nodes[%d].depends_on", index)
			if dependency == node.ID {
				add("ERROR", "self_dependency", path, "node cannot depend on itself")
			} else if _, exists := nodes[dependency]; !exists {
				add("ERROR", "unknown_dependency", path, "dependency "+dependency+" does not exist")
			} else if seenDependency[dependency] {
				add("ERROR", "duplicate_dependency", path, "dependency "+dependency+" is repeated")
			}
			seenDependency[dependency] = true
		}
	}
	if roots == 0 && len(spec.Nodes) > 0 {
		add("ERROR", "missing_root", "nodes", "playbook must have at least one root node")
	}
	if cycle := detectCycle(nodes); len(cycle) > 0 {
		add("ERROR", "cycle", "nodes", "playbook graph contains a cycle: "+strings.Join(cycle, " -> "))
	}
	for index, node := range spec.Nodes {
		if node.Type != core.SOARNodeAction {
			continue
		}
		actionType, _ := configString(node.Config, "action_type")
		descriptor, exists := v.Actions[actionType]
		if !exists {
			continue
		}
		mode, _ := configString(node.Config, "mode")
		mode = strings.ToUpper(mode)
		if mode == "" {
			mode = "DRY_RUN"
		}
		required := 0
		switch descriptor.Level {
		case 4:
			required = 1
		case 5, 6:
			required = 2
		}
		if descriptor.Level == 6 && mode == "LIVE" {
			add("ERROR", "destructive_disabled", fmt.Sprintf("nodes[%d].config.mode", index),
				"A6 live actions are disabled for university deployments")
		}
		if required > 0 && maximumApprovalAncestors(node.ID, nodes) < required {
			add("ERROR", "approval_required", fmt.Sprintf("nodes[%d].depends_on", index),
				fmt.Sprintf("A%d action requires an approval ancestor with at least %d independent approval(s)", descriptor.Level, required))
		}
		if descriptor.Level >= 3 && mode == "LIVE" {
			verify, _ := node.Config["verify"].(bool)
			if !verify {
				add("ERROR", "verification_required", fmt.Sprintf("nodes[%d].config.verify", index),
					"live containment actions require verification")
			}
		}
		if descriptor.Level == 3 && mode == "LIVE" {
			compensation, _ := configString(node.Config, "compensation_action")
			if !descriptor.Reversible || compensation == "" {
				add("ERROR", "compensation_required", fmt.Sprintf("nodes[%d].config.compensation_action", index),
					"A3 live containment requires a reversible compensation action")
			}
		}
	}
	sort.SliceStable(report.Issues, func(i, j int) bool {
		if report.Issues[i].Level == report.Issues[j].Level {
			return report.Issues[i].Path < report.Issues[j].Path
		}
		return report.Issues[i].Level == "ERROR"
	})
	report.Valid = true
	for _, issue := range report.Issues {
		if issue.Level == "ERROR" {
			report.Valid = false
			break
		}
	}
	return report
}

func validateNode(actions ActionCatalog, node core.SOARNode, path string, add func(string, string, string, string)) {
	allowedTypes := map[string]bool{
		core.SOARNodeTrigger: true, core.SOARNodeCondition: true, core.SOARNodeAction: true,
		core.SOARNodeTransform: true, core.SOARNodeLoop: true, core.SOARNodeParallel: true,
		core.SOARNodeDelay: true, core.SOARNodeRetry: true, core.SOARNodeApproval: true,
		core.SOARNodeSubPlaybook: true, core.SOARNodeManualTask: true, core.SOARNodeWebhook: true,
		core.SOARNodeNotification: true,
	}
	if !allowedTypes[node.Type] {
		add("ERROR", "node_type", path+".type", "unsupported node type "+node.Type)
	}
	if strings.TrimSpace(node.Name) == "" || len(node.Name) > 160 {
		add("ERROR", "node_name", path+".name", "node name must contain 1 to 160 characters")
	}
	if node.TimeoutSeconds < 0 || node.TimeoutSeconds > 3600 {
		add("ERROR", "timeout", path+".timeout_seconds", "timeout must be between 0 and 3600 seconds")
	}
	if node.Retry.MaximumAttempts < 0 || node.Retry.MaximumAttempts > 5 ||
		node.Retry.BackoffSeconds < 0 || node.Retry.BackoffSeconds > 3600 ||
		node.Retry.MaximumBackoff < 0 || node.Retry.MaximumBackoff > 86400 {
		add("ERROR", "retry_policy", path+".retry", "retry policy exceeds safe bounds")
	}
	if dangerousConfig(node.Config) {
		add("ERROR", "arbitrary_code", path+".config", "script, shell, command, code, and exec configuration is forbidden")
	}
	switch node.Type {
	case core.SOARNodeAction:
		actionType, ok := configString(node.Config, "action_type")
		if !ok {
			add("ERROR", "action_type", path+".config.action_type", "action_type is required")
			break
		}
		descriptor, exists := actions[actionType]
		if !exists {
			add("ERROR", "unknown_action", path+".config.action_type", "action is not present in the server-side catalog")
			break
		}
		mode, _ := configString(node.Config, "mode")
		mode = strings.ToUpper(mode)
		if mode != "" && mode != "DRY_RUN" && mode != "LIVE" {
			add("ERROR", "action_mode", path+".config.mode", "mode must be DRY_RUN or LIVE")
		}
		if requested, ok := configInt(node.Config, "risk_level"); ok && requested != descriptor.Level {
			add("ERROR", "risk_spoofing", path+".config.risk_level", "risk level is assigned by the server action catalog")
		}
	case core.SOARNodeApproval:
		required, ok := configInt(node.Config, "required_approvals")
		if !ok || required < 1 || required > 2 {
			add("ERROR", "approval_count", path+".config.required_approvals", "required_approvals must be 1 or 2")
		}
	case core.SOARNodeDelay:
		delay, ok := configInt(node.Config, "duration_seconds")
		if !ok || delay < 1 || delay > 86400 {
			add("ERROR", "delay", path+".config.duration_seconds", "delay must be between 1 second and 24 hours")
		}
	case core.SOARNodeLoop:
		iterations, ok := configInt(node.Config, "maximum_iterations")
		if !ok || iterations < 1 || iterations > 100 {
			add("ERROR", "loop_bound", path+".config.maximum_iterations", "loop requires a maximum of 1 to 100 iterations")
		}
	case core.SOARNodeWebhook:
		add("WARNING", "connector_required", path, "webhook execution requires a registered connector and secret binding")
	}
}

func dangerousConfig(value interface{}) bool {
	switch item := value.(type) {
	case map[string]interface{}:
		for key, nested := range item {
			switch strings.ToLower(strings.TrimSpace(key)) {
			case "script", "shell", "command", "code", "exec":
				return true
			}
			if dangerousConfig(nested) {
				return true
			}
		}
	case []interface{}:
		for _, nested := range item {
			if dangerousConfig(nested) {
				return true
			}
		}
	}
	return false
}

func detectCycle(nodes map[string]core.SOARNode) []string {
	const visiting = 1
	const visited = 2
	state := map[string]int{}
	stack := []string{}
	var visit func(string) []string
	visit = func(id string) []string {
		if state[id] == visiting {
			for index, item := range stack {
				if item == id {
					return append(append([]string{}, stack[index:]...), id)
				}
			}
			return []string{id, id}
		}
		if state[id] == visited {
			return nil
		}
		state[id] = visiting
		stack = append(stack, id)
		for _, dependency := range nodes[id].DependsOn {
			if _, exists := nodes[dependency]; !exists {
				continue
			}
			if cycle := visit(dependency); len(cycle) > 0 {
				return cycle
			}
		}
		stack = stack[:len(stack)-1]
		state[id] = visited
		return nil
	}
	keys := make([]string, 0, len(nodes))
	for id := range nodes {
		keys = append(keys, id)
	}
	sort.Strings(keys)
	for _, id := range keys {
		if cycle := visit(id); len(cycle) > 0 {
			return cycle
		}
	}
	return nil
}

func maximumApprovalAncestors(nodeID string, nodes map[string]core.SOARNode) int {
	visited := map[string]bool{}
	maximum := 0
	var walk func(string)
	walk = func(id string) {
		for _, dependency := range nodes[id].DependsOn {
			if visited[dependency] {
				continue
			}
			visited[dependency] = true
			node, exists := nodes[dependency]
			if !exists {
				continue
			}
			if node.Type == core.SOARNodeApproval {
				if count, ok := configInt(node.Config, "required_approvals"); ok && count > maximum {
					maximum = count
				}
			}
			walk(dependency)
		}
	}
	walk(nodeID)
	return maximum
}

func configString(config map[string]interface{}, key string) (string, bool) {
	value, ok := config[key].(string)
	return strings.TrimSpace(value), ok && strings.TrimSpace(value) != ""
}

func configInt(config map[string]interface{}, key string) (int, bool) {
	switch value := config[key].(type) {
	case int:
		return value, true
	case float64:
		if value == float64(int(value)) {
			return int(value), true
		}
	case json.Number:
		parsed, err := value.Int64()
		return int(parsed), err == nil
	}
	return 0, false
}
