package detection

import (
	"errors"
	"testing"

	"github.com/kcsp/platform/internal/core"
)

const sigmaPowerShell = `title: Encoded PowerShell through Sysmon
id: KCSP-SIGMA-PS-001
status: test
description: Detects encoded PowerShell commands outside the approved deployment account.
author: KCSP Detection Engineering
level: high
confidence: 88
logsource:
  product: windows
  service: sysmon
tags:
  - attack.execution
  - attack.t1059.001
falsepositives:
  - Approved deployment automation
detection:
  selection_image:
    category: process_activity
    process.name|endswith:
      - powershell.exe
      - pwsh.exe
  selection_command:
    process.command_line|contains:
      - encodedcommand
      - " -enc "
  approved_account:
    user.name: KCSP\deployment
  condition: all of selection_* and not approved_account
`

func TestCompileAndEvaluateSigmaBooleanAST(t *testing.T) {
	compiled, err := Compile(core.DetectionContent{RuleID: "KCSP-SIGMA-PS-001", Version: "1.0.0", State: "VALIDATED", SigmaYAML: sigmaPowerShell})
	if err != nil {
		t.Fatal(err)
	}
	matched, fields := compiled.Evaluate(core.CanonicalEvent{
		Category: "process_activity", User: core.UserRef{Name: `KCSP\admin`},
		Process: core.ProcessRef{Name: "PowerShell.EXE", CommandLine: "powershell.exe -EncodedCommand SQBFAFgA"},
	})
	if !matched || len(fields) != 3 {
		t.Fatalf("expected match and three fields, matched=%v fields=%v", matched, fields)
	}
	approved, _ := compiled.Evaluate(core.CanonicalEvent{
		Category: "process_activity", User: core.UserRef{Name: `KCSP\deployment`},
		Process: core.ProcessRef{Name: "powershell.exe", CommandLine: "powershell.exe -enc SQBFAFgA"},
	})
	if approved {
		t.Fatal("negative filter did not suppress approved account")
	}
	if compiled.Rule.Severity != core.SeverityHigh || compiled.Rule.Confidence != 88 || len(compiled.Rule.MITRE) != 1 || compiled.Rule.MITRE[0] != "T1059.001" {
		t.Fatalf("Sigma metadata mapping failed: %+v", compiled.Rule)
	}
}

func TestCompileRejectsUnsupportedModifierAndUnknownSelection(t *testing.T) {
	cases := []string{
		"title: X\nid: x\ndetection:\n  s:\n    process.name|re: powershell\n  condition: s\n",
		"title: X\nid: x\ndetection:\n  s:\n    process.name: powershell\n  condition: missing\n",
	}
	for _, source := range cases {
		_, err := Compile(core.DetectionContent{RuleID: "x", Version: "1", SigmaYAML: source})
		if !errors.Is(err, ErrInvalidRule) {
			t.Fatalf("expected ErrInvalidRule, got %v", err)
		}
	}
}
