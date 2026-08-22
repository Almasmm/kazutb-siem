package soar

import (
	"testing"

	"github.com/kcsp/platform/internal/core"
)

func TestValidatorAcceptsApprovedA4DAG(t *testing.T) {
	spec := core.SOARPlaybookSpec{
		SchemaVersion: "1.0", Trigger: core.SOARTrigger{Type: "INCIDENT"},
		Nodes: []core.SOARNode{
			{ID: "enrich", Type: core.SOARNodeAction, Name: "Enrich", Config: map[string]interface{}{
				"action_type": "kcsp.enrich.threat_intel", "mode": "LIVE",
			}},
			{ID: "approve", Type: core.SOARNodeApproval, Name: "Approve account disable", DependsOn: []string{"enrich"},
				Config: map[string]interface{}{"required_approvals": 1}},
			{ID: "disable", Type: core.SOARNodeAction, Name: "Disable account", DependsOn: []string{"approve"},
				Config: map[string]interface{}{"action_type": "identity.disable_account", "mode": "LIVE", "verify": true}},
		},
	}
	report := NewValidator(nil).Validate(spec)
	if !report.Valid || report.SpecHash == "" || report.NodeCount != 3 {
		t.Fatalf("valid playbook was rejected: %+v", report)
	}
}

func TestValidatorRejectsCycleCodeRiskSpoofAndUnapprovedA5(t *testing.T) {
	spec := core.SOARPlaybookSpec{
		SchemaVersion: "1.0", Trigger: core.SOARTrigger{Type: "ALERT"},
		Nodes: []core.SOARNode{
			{ID: "one", Type: core.SOARNodeTransform, Name: "Unsafe", DependsOn: []string{"two"},
				Config: map[string]interface{}{"script": "rm -rf /"}},
			{ID: "two", Type: core.SOARNodeAction, Name: "Firewall block", DependsOn: []string{"one"},
				Config: map[string]interface{}{"action_type": "firewall.block_ip", "mode": "LIVE", "risk_level": 1}},
		},
	}
	report := NewValidator(nil).Validate(spec)
	if report.Valid {
		t.Fatalf("unsafe playbook was accepted: %+v", report)
	}
	for _, code := range []string{"cycle", "arbitrary_code", "risk_spoofing", "approval_required", "verification_required"} {
		if !hasIssue(report, code) {
			t.Errorf("missing validation issue %s: %+v", code, report.Issues)
		}
	}
}

func TestValidatorDisablesLiveA6EvenWithDualApproval(t *testing.T) {
	spec := core.SOARPlaybookSpec{
		SchemaVersion: "1.0", Trigger: core.SOARTrigger{Type: "MANUAL"},
		Nodes: []core.SOARNode{
			{ID: "approve", Type: core.SOARNodeApproval, Name: "Dual approval",
				Config: map[string]interface{}{"required_approvals": 2}},
			{ID: "destroy", Type: core.SOARNodeAction, Name: "Destructive action", DependsOn: []string{"approve"},
				Config: map[string]interface{}{"action_type": "destructive.erase_evidence", "mode": "LIVE", "verify": true}},
		},
	}
	report := NewValidator(nil).Validate(spec)
	if report.Valid || !hasIssue(report, "destructive_disabled") {
		t.Fatalf("live A6 action was not denied: %+v", report)
	}
}

func hasIssue(report core.SOARValidationReport, code string) bool {
	for _, issue := range report.Issues {
		if issue.Code == code {
			return true
		}
	}
	return false
}
