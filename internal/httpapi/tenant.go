package httpapi

import (
	"strings"

	"github.com/kcsp/platform/internal/platform/tenant"
)

// tenantIDFromHeader returns an empty ID on every ambiguous or malformed
// representation. The authorization middleware handles an empty result as a
// tenant denial, keeping duplicate-header and proxy-merge behavior fail closed.
func tenantIDFromHeader(values []string) string {
	if len(values) != 1 {
		return ""
	}
	value := strings.TrimSpace(values[0])
	if !tenant.Valid(value) {
		return ""
	}
	return value
}
