package threatintel

import (
	"testing"

	"github.com/kcsp/platform/internal/core"
)

func TestNormalizeValueProducesStableIOCIdentities(t *testing.T) {
	tests := []struct {
		kind  core.ThreatIndicatorType
		value string
		want  string
	}{
		{core.ThreatIndicatorIPv4, "203.0.113.7", "203.0.113.7"},
		{core.ThreatIndicatorIPv6, "2001:0db8:0:0::1", "2001:db8::1"},
		{core.ThreatIndicatorDomain, "Evil.Example.", "evil.example"},
		{core.ThreatIndicatorURL, "HTTPS://Evil.Example:443/a?b=2&a=1#fragment", "https://evil.example/a?a=1&b=2"},
		{core.ThreatIndicatorEmail, "SOC@Evil.Example", "soc@evil.example"},
		{core.ThreatIndicatorHash, "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		{core.ThreatIndicatorCertificateFingerprint, "AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
	}
	for _, test := range tests {
		got, err := NormalizeValue(test.kind, test.value)
		if err != nil {
			t.Fatalf("normalize %s: %v", test.kind, err)
		}
		if got != test.want {
			t.Fatalf("normalize %s: got %q want %q", test.kind, got, test.want)
		}
	}
}

func TestNormalizeValueRejectsMalformedObservables(t *testing.T) {
	for _, test := range []struct {
		kind  core.ThreatIndicatorType
		value string
	}{
		{core.ThreatIndicatorIPv4, "999.1.1.1"},
		{core.ThreatIndicatorDomain, "-bad.example"},
		{core.ThreatIndicatorURL, "file:///etc/passwd"},
		{core.ThreatIndicatorHash, "not-a-hash"},
		{core.ThreatIndicatorEmail, "not-an-email"},
	} {
		if _, err := NormalizeValue(test.kind, test.value); err == nil {
			t.Fatalf("accepted malformed %s value %q", test.kind, test.value)
		}
	}
}

func TestExtractObservablesUsesExplicitCanonicalFields(t *testing.T) {
	event := core.CanonicalEvent{
		SrcEndpoint: core.EndpointRef{IP: "203.0.113.7"},
		Metadata: map[string]interface{}{
			"http": map[string]interface{}{"url": "https://evil.example/dropper?a=1"},
			"file": map[string]interface{}{"sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		},
	}
	observables := ExtractObservables(event)
	required := map[string]bool{
		"IPV4|203.0.113.7|src_endpoint.ip":                                                           false,
		"URL|https://evil.example/dropper?a=1|metadata.http.url":                                     false,
		"DOMAIN|evil.example|metadata.http.url.host":                                                 false,
		"HASH|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa|metadata.file.sha256": false,
	}
	for _, observable := range observables {
		key := string(observable.Type) + "|" + observable.NormalizedValue + "|" + observable.Field
		if _, ok := required[key]; ok {
			required[key] = true
		}
	}
	for key, found := range required {
		if !found {
			t.Errorf("missing observable %s: %+v", key, observables)
		}
	}
}
