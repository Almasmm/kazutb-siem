package soar

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/kcsp/platform/internal/core"
)

func TestApprovalDecisionRequestIsStrict(t *testing.T) {
	valid := []ApprovalDecisionRequest{
		{Decision: core.ApprovalDecisionApprove, Reason: "Reviewed", Version: 1},
		{Decision: core.ApprovalDecisionReject, Reason: "Unsafe", Version: 2},
	}
	for _, request := range valid {
		if !request.Decision.Valid() || request.Version < 1 || len(strings.TrimSpace(request.Reason)) < 2 {
			t.Fatalf("canonical request rejected: %+v", request)
		}
	}

	invalid := []core.ApprovalDecision{"", "APPROVED", "REJECTED", "approved", "Approved", "reject", "rejected", "APPROVE ", " APPROVE", "UNKNOWN"}
	for _, decision := range invalid {
		if decision.Valid() {
			t.Fatalf("non-canonical decision accepted: %q", decision)
		}
	}
}

func TestApprovalDecisionJSONRejectsMalformedTypes(t *testing.T) {
	payloads := []string{
		`{"decision":true,"reason":"x","version":1}`,
		`{"decision":1,"reason":"x","version":1}`,
		`{"decision":{},"reason":"x","version":1}`,
		`{"decision":[],"reason":"x","version":1}`,
		`{"decision":"APPROVE","reason":"x","version":1`,
	}
	for _, payload := range payloads {
		decoder := json.NewDecoder(strings.NewReader(payload))
		decoder.DisallowUnknownFields()
		var request ApprovalDecisionRequest
		if err := decoder.Decode(&request); err == nil {
			t.Fatalf("malformed decision payload decoded: %s", payload)
		}
	}
	var nullRequest ApprovalDecisionRequest
	if err := json.Unmarshal([]byte(`{"decision":null,"reason":"Reviewed","version":1}`), &nullRequest); err != nil {
		t.Fatal(err)
	}
	if nullRequest.Decision.Valid() {
		t.Fatal("null decision became a valid command")
	}
}

func TestApprovalDecisionJSONRejectsMassAssignment(t *testing.T) {
	decoder := json.NewDecoder(strings.NewReader(`{"decision":"APPROVE","reason":"Reviewed","version":1,"tenant_id":"other"}`))
	decoder.DisallowUnknownFields()
	var request ApprovalDecisionRequest
	if err := decoder.Decode(&request); err == nil {
		t.Fatal("unknown tenant field was accepted")
	}
}
