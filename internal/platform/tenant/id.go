// Package tenant defines the canonical tenant identity shared by KCSP trust
// boundaries. Keeping this validation independent from HTTP and OIDC prevents
// path, object-key, and case-folding ambiguities between platform components.
package tenant

import "errors"

const MaxIDLength = 63

var ErrInvalidID = errors.New("invalid tenant ID")

// Valid reports whether value is a canonical KCSP tenant identifier. Tenant
// IDs intentionally follow a single DNS-label-like representation so they can
// be used consistently in claims, headers, database keys, and object prefixes.
func Valid(value string) bool {
	if value == "" || len(value) > MaxIDLength || !isLowerAlphaNumeric(value[0]) || !isLowerAlphaNumeric(value[len(value)-1]) {
		return false
	}
	for index := 1; index < len(value)-1; index++ {
		if !isLowerAlphaNumeric(value[index]) && value[index] != '-' {
			return false
		}
	}
	return true
}

func Validate(value string) error {
	if !Valid(value) {
		return ErrInvalidID
	}
	return nil
}

func isLowerAlphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}
