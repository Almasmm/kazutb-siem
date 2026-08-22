package core

import "testing"

func TestSeverityMappingAndIdentityGeneration(t *testing.T) {
	tests := []struct {
		risk int
		want Severity
	}{
		{0, SeverityInformational}, {20, SeverityLow}, {40, SeverityMedium},
		{65, SeverityHigh}, {85, SeverityCritical}, {100, SeverityCritical},
	}
	for _, test := range tests {
		if got := SeverityFromRisk(test.risk); got != test.want {
			t.Fatalf("risk %d mapped to %s, want %s", test.risk, got, test.want)
		}
	}
	left, right := NewID("evt"), NewID("evt")
	if left == right || len(left) <= len("evt_") || left[:4] != "evt_" {
		t.Fatalf("unexpected generated ids: %q %q", left, right)
	}
}
