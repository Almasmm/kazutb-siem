package threatintel

import (
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/kcsp/platform/internal/core"
)

func NormalizeIndicatorType(value core.ThreatIndicatorType) (core.ThreatIndicatorType, error) {
	normalized := core.ThreatIndicatorType(strings.ToUpper(strings.TrimSpace(string(value))))
	switch normalized {
	case core.ThreatIndicatorIPv4, core.ThreatIndicatorIPv6, core.ThreatIndicatorDomain,
		core.ThreatIndicatorURL, core.ThreatIndicatorHash, core.ThreatIndicatorEmail,
		core.ThreatIndicatorCertificateFingerprint:
		return normalized, nil
	default:
		return "", fmt.Errorf("%w: unsupported indicator type %q", ErrInvalidIndicator, value)
	}
}

func NormalizeValue(indicatorType core.ThreatIndicatorType, value string) (string, error) {
	indicatorType, err := NormalizeIndicatorType(indicatorType)
	if err != nil {
		return "", err
	}
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 4096 {
		return "", fmt.Errorf("%w: indicator value must contain 1 to 4096 characters", ErrInvalidIndicator)
	}
	switch indicatorType {
	case core.ThreatIndicatorIPv4:
		ip := net.ParseIP(value)
		if ip == nil || ip.To4() == nil {
			return "", fmt.Errorf("%w: malformed IPv4 address", ErrInvalidIndicator)
		}
		return ip.To4().String(), nil
	case core.ThreatIndicatorIPv6:
		ip := net.ParseIP(value)
		if ip == nil || ip.To4() != nil {
			return "", fmt.Errorf("%w: malformed IPv6 address", ErrInvalidIndicator)
		}
		return ip.String(), nil
	case core.ThreatIndicatorDomain:
		return normalizeDomain(value)
	case core.ThreatIndicatorURL:
		return normalizeURL(value)
	case core.ThreatIndicatorHash:
		return normalizeHash(value, false)
	case core.ThreatIndicatorEmail:
		address, err := mail.ParseAddress(value)
		if err != nil || !strings.Contains(address.Address, "@") {
			return "", fmt.Errorf("%w: malformed email address", ErrInvalidIndicator)
		}
		parts := strings.Split(address.Address, "@")
		if len(parts) != 2 || parts[0] == "" {
			return "", fmt.Errorf("%w: malformed email address", ErrInvalidIndicator)
		}
		domain, err := normalizeDomain(parts[1])
		if err != nil {
			return "", fmt.Errorf("%w: malformed email address", ErrInvalidIndicator)
		}
		return strings.ToLower(parts[0]) + "@" + domain, nil
	case core.ThreatIndicatorCertificateFingerprint:
		return normalizeHash(value, true)
	default:
		return "", fmt.Errorf("%w: unsupported indicator type", ErrInvalidIndicator)
	}
}

func ExtractObservables(event core.CanonicalEvent) []core.ThreatObservable {
	result := make([]core.ThreatObservable, 0, 16)
	seen := map[string]bool{}
	add := func(indicatorType core.ThreatIndicatorType, rawValue, field string) {
		normalized, err := NormalizeValue(indicatorType, rawValue)
		if err != nil {
			return
		}
		key := string(indicatorType) + "\x00" + normalized + "\x00" + field
		if seen[key] {
			return
		}
		seen[key] = true
		result = append(result, core.ThreatObservable{
			Type: indicatorType, NormalizedValue: normalized, Field: field, RawValue: strings.TrimSpace(rawValue),
		})
	}
	addIP := func(value, field string) {
		ip := net.ParseIP(strings.TrimSpace(value))
		if ip == nil {
			return
		}
		if ip.To4() != nil {
			add(core.ThreatIndicatorIPv4, value, field)
		} else {
			add(core.ThreatIndicatorIPv6, value, field)
		}
	}
	addHost := func(value, field string) {
		addIP(value, field)
		add(core.ThreatIndicatorDomain, value, field)
	}
	addIP(event.SrcEndpoint.IP, "src_endpoint.ip")
	addIP(event.DstEndpoint.IP, "dst_endpoint.ip")
	addIP(event.Device.IP, "device.ip")
	addHost(event.SrcEndpoint.Hostname, "src_endpoint.hostname")
	addHost(event.DstEndpoint.Hostname, "dst_endpoint.hostname")
	addHost(event.Device.Hostname, "device.hostname")
	if strings.Contains(event.User.Name, "@") {
		add(core.ThreatIndicatorEmail, event.User.Name, "user.name")
	}

	for _, item := range []struct {
		key  string
		kind core.ThreatIndicatorType
	}{
		{"url", core.ThreatIndicatorURL}, {"http.url", core.ThreatIndicatorURL}, {"request.url", core.ThreatIndicatorURL},
		{"domain", core.ThreatIndicatorDomain}, {"dns.query", core.ThreatIndicatorDomain},
		{"email", core.ThreatIndicatorEmail}, {"user.email", core.ThreatIndicatorEmail},
		{"hash", core.ThreatIndicatorHash}, {"file.hash", core.ThreatIndicatorHash},
		{"file.sha256", core.ThreatIndicatorHash}, {"process.hash", core.ThreatIndicatorHash},
		{"certificate.fingerprint", core.ThreatIndicatorCertificateFingerprint},
	} {
		value := metadataString(event.Metadata, item.key)
		if value == "" {
			continue
		}
		add(item.kind, value, "metadata."+item.key)
		if item.kind == core.ThreatIndicatorURL {
			parsed, err := url.Parse(value)
			if err == nil {
				addHost(parsed.Hostname(), "metadata."+item.key+".host")
			}
		}
	}
	sort.SliceStable(result, func(i, j int) bool {
		if result[i].Field == result[j].Field {
			if result[i].Type == result[j].Type {
				return result[i].NormalizedValue < result[j].NormalizedValue
			}
			return result[i].Type < result[j].Type
		}
		return result[i].Field < result[j].Field
	})
	return result
}

func normalizeDomain(value string) (string, error) {
	value = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
	if value == "" || len(value) > 253 || net.ParseIP(value) != nil {
		return "", fmt.Errorf("%w: malformed domain", ErrInvalidIndicator)
	}
	labels := strings.Split(value, ".")
	if len(labels) < 2 {
		return "", fmt.Errorf("%w: domain must contain a public or private suffix", ErrInvalidIndicator)
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("%w: malformed domain label", ErrInvalidIndicator)
		}
		for _, r := range label {
			if !(unicode.IsDigit(r) || (r >= 'a' && r <= 'z') || r == '-') {
				return "", fmt.Errorf("%w: domains must use ASCII or punycode", ErrInvalidIndicator)
			}
		}
	}
	return value, nil
}

func normalizeURL(value string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || parsed.Host == "" || parsed.User != nil {
		return "", fmt.Errorf("%w: malformed URL", ErrInvalidIndicator)
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("%w: only http and https URLs are supported", ErrInvalidIndicator)
	}
	host := parsed.Hostname()
	if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
	} else {
		host, err = normalizeDomain(host)
		if err != nil {
			return "", fmt.Errorf("%w: malformed URL host", ErrInvalidIndicator)
		}
	}
	port := parsed.Port()
	if (parsed.Scheme == "http" && port == "80") || (parsed.Scheme == "https" && port == "443") {
		port = ""
	}
	if port != "" {
		portNumber, parseErr := strconv.Atoi(port)
		if parseErr != nil || portNumber < 1 || portNumber > 65535 {
			return "", fmt.Errorf("%w: malformed URL port", ErrInvalidIndicator)
		}
		parsed.Host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		parsed.Host = "[" + host + "]"
	} else {
		parsed.Host = host
	}
	if parsed.Path == "" {
		parsed.Path = "/"
	}
	parsed.RawQuery = parsed.Query().Encode()
	parsed.Fragment = ""
	return parsed.String(), nil
}

func normalizeHash(value string, certificate bool) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	for _, prefix := range []string{"md5:", "sha1:", "sha256:", "sha512:"} {
		value = strings.TrimPrefix(value, prefix)
	}
	if certificate {
		value = strings.NewReplacer(":", "", "-", "", " ", "").Replace(value)
	}
	validLength := map[int]bool{32: true, 40: true, 64: true, 128: true}
	if certificate {
		validLength = map[int]bool{40: true, 64: true, 128: true}
	}
	if !validLength[len(value)] {
		return "", fmt.Errorf("%w: unsupported hash length", ErrInvalidIndicator)
	}
	for _, r := range value {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return "", fmt.Errorf("%w: hash must be hexadecimal", ErrInvalidIndicator)
		}
	}
	return value, nil
}

func metadataString(metadata map[string]interface{}, key string) string {
	if metadata == nil {
		return ""
	}
	if direct, ok := metadata[key]; ok {
		if value, ok := direct.(string); ok {
			return value
		}
	}
	var current interface{} = metadata
	for _, segment := range strings.Split(key, ".") {
		object, ok := current.(map[string]interface{})
		if !ok {
			return ""
		}
		current, ok = object[segment]
		if !ok {
			return ""
		}
	}
	value, _ := current.(string)
	return value
}
