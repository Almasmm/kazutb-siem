package tenant

import (
	"strings"
	"testing"
)

func TestValidTenantID(t *testing.T) {
	t.Parallel()
	valid := []string{
		"a",
		"tenant-a",
		"university-kulazhanov",
		strings.Repeat("a", MaxIDLength),
	}
	for _, value := range valid {
		value := value
		t.Run(value, func(t *testing.T) {
			t.Parallel()
			if err := Validate(value); err != nil {
				t.Fatalf("Validate(%q): %v", value, err)
			}
		})
	}
}

func TestInvalidTenantID(t *testing.T) {
	t.Parallel()
	invalid := []string{
		"",
		" Tenant-a",
		"tenant-a ",
		"Tenant-a",
		"tenant_a",
		"tenant.a",
		"tenant/a",
		"../tenant-a",
		"-tenant-a",
		"tenant-a-",
		"tenant--a/other",
		"тенант",
		strings.Repeat("a", MaxIDLength+1),
	}
	for _, value := range invalid {
		value := value
		t.Run(value, func(t *testing.T) {
			t.Parallel()
			if Valid(value) {
				t.Fatalf("Valid(%q) = true", value)
			}
		})
	}
}
