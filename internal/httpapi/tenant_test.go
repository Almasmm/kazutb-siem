package httpapi

import "testing"

func TestTenantIDFromHeaderFailsClosed(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		values []string
		want   string
	}{
		{name: "canonical", values: []string{"tenant-a"}, want: "tenant-a"},
		{name: "optional whitespace", values: []string{" tenant-a "}, want: "tenant-a"},
		{name: "missing"},
		{name: "duplicate", values: []string{"tenant-a", "tenant-b"}},
		{name: "proxy merged", values: []string{"tenant-a, tenant-b"}},
		{name: "path confusion", values: []string{"tenant-a/../tenant-b"}},
		{name: "case confusion", values: []string{"Tenant-a"}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := tenantIDFromHeader(test.values); got != test.want {
				t.Fatalf("tenantIDFromHeader(%q) = %q, want %q", test.values, got, test.want)
			}
		})
	}
}
