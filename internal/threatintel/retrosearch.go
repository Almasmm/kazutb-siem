package threatintel

import (
	"fmt"

	"github.com/kcsp/platform/internal/core"
)

func RetrosearchExpression(indicator core.ThreatIndicator) (*core.HuntExpression, error) {
	fields := []string{}
	switch indicator.Type {
	case core.ThreatIndicatorIPv4, core.ThreatIndicatorIPv6:
		fields = []string{"src_endpoint.ip", "dst_endpoint.ip", "device.ip", "metadata.source_ip", "metadata.destination_ip"}
	case core.ThreatIndicatorDomain:
		fields = []string{"src_endpoint.hostname", "dst_endpoint.hostname", "device.hostname", "metadata.domain", "metadata.dns.query"}
	case core.ThreatIndicatorURL:
		fields = []string{"metadata.url", "metadata.http.url", "metadata.request.url"}
	case core.ThreatIndicatorHash:
		fields = []string{"metadata.hash", "metadata.file.hash", "metadata.file.sha256", "metadata.process.hash"}
	case core.ThreatIndicatorEmail:
		fields = []string{"user.name", "metadata.email", "metadata.user.email"}
	case core.ThreatIndicatorCertificateFingerprint:
		fields = []string{"metadata.certificate.fingerprint"}
	default:
		return nil, fmt.Errorf("%w: unsupported retrosearch indicator type %q", ErrInvalidIndicator, indicator.Type)
	}
	any := make([]core.HuntExpression, 0, len(fields))
	for _, field := range fields {
		predicate := core.HuntPredicate{Field: field, Comparator: "eq", Value: indicator.NormalizedValue}
		any = append(any, core.HuntExpression{Predicate: &predicate})
	}
	return &core.HuntExpression{Any: any}, nil
}
