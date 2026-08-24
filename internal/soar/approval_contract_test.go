package soar

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestApprovalContractHasNoFrontendBackendOpenAPIDrift(t *testing.T) {
	_, current, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(current), "..", ".."))
	files := map[string]string{
		"openapi":  filepath.Join(root, "api", "openapi", "kcsp-v0.1.yaml"),
		"backend":  filepath.Join(root, "internal", "core", "soar.go"),
		"types":    filepath.Join(root, "apps", "web", "src", "api", "types.ts"),
		"mutation": filepath.Join(root, "apps", "web", "src", "soar", "approval.ts"),
		"page":     filepath.Join(root, "apps", "web", "src", "pages", "SoarPage.tsx"),
	}
	contents := map[string]string{}
	for name, path := range files {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s contract: %v", name, err)
		}
		contents[name] = string(body)
	}
	for _, required := range []string{"ApprovalDecision:\n      type: string\n      enum: [APPROVE, REJECT]", "ApprovalStatus:\n      type: string\n      enum: [PENDING, APPROVED, REJECTED, EXPIRED, CANCELLED]"} {
		if !strings.Contains(contents["openapi"], required) {
			t.Fatalf("OpenAPI contract missing %q", required)
		}
	}
	if !strings.Contains(contents["backend"], `ApprovalDecisionApprove ApprovalDecision = "APPROVE"`) || !strings.Contains(contents["backend"], `ApprovalDecisionReject  ApprovalDecision = "REJECT"`) {
		t.Fatal("backend decision enum drifted")
	}
	if !strings.Contains(contents["types"], `APPROVE: "APPROVE"`) || !strings.Contains(contents["types"], `REJECT: "REJECT"`) {
		t.Fatal("frontend decision enum drifted")
	}
	if !strings.Contains(contents["mutation"], "return { decision, reason: normalizedReason, version }") {
		t.Fatal("frontend mutation no longer binds the typed decision directly")
	}
	if strings.Contains(contents["page"], `value="APPROVED"`) || strings.Contains(contents["page"], `value="REJECTED"`) {
		t.Fatal("frontend page uses resulting statuses as request commands")
	}
}
