#!/usr/bin/env bash
set -Eeuo pipefail

base_url="${1:?usage: security-headers-self-test.sh BASE_URL [OIDC_ORIGIN]}"
oidc_origin="${2:-}"

fail() {
  printf 'web-security-self-test: %s\n' "$*" >&2
  exit 1
}

for command_name in curl grep head tr; do
  command -v "$command_name" >/dev/null 2>&1 || fail "$command_name is required"
done

request_headers() {
  curl --fail --silent --show-error --dump-header - --output /dev/null "$1" \
    | tr -d '\r' \
    | tr '[:upper:]' '[:lower:]'
}

assert_header() {
  local headers="$1" name="$2" expected="$3"
  grep -Fqx "${name}: ${expected}" <<<"$headers" || fail "missing ${name}: ${expected}"
}

assert_security_headers() {
  local path="$1" headers csp
  headers="$(request_headers "$base_url$path")"
  assert_header "$headers" x-content-type-options nosniff
  assert_header "$headers" x-frame-options deny
  assert_header "$headers" referrer-policy no-referrer
  assert_header "$headers" permissions-policy "camera=(), microphone=(), geolocation=()"
  assert_header "$headers" cross-origin-opener-policy same-origin
  assert_header "$headers" cross-origin-resource-policy same-origin
  assert_header "$headers" strict-transport-security "max-age=31536000; includesubdomains"
  csp="$(grep '^content-security-policy:' <<<"$headers" || true)"
  [[ "$csp" == *"default-src 'self'"* && "$csp" == *"frame-ancestors 'none'"* && "$csp" == *"object-src 'none'"* ]] \
    || fail "CSP is missing on $path"
  if [[ -n "$oidc_origin" ]]; then
    [[ "$csp" == *"connect-src 'self' $oidc_origin"* && "$csp" == *"frame-src 'self' $oidc_origin"* ]] \
      || fail "CSP does not permit only the configured OIDC origin"
  fi
  printf '%s' "$headers"
}

index="$(curl --fail --silent --show-error "$base_url/")"
asset="$(grep -oE '/assets/[^" ]+\.js' <<<"$index" | head -n 1)"
[[ -n "$asset" ]] || fail "could not discover a built JavaScript asset"

root_headers="$(assert_security_headers /)"
config_headers="$(assert_security_headers /config.js)"
asset_headers="$(assert_security_headers "$asset")"
assert_header "$root_headers" cache-control no-store
assert_header "$config_headers" cache-control no-store
assert_header "$asset_headers" cache-control "public, max-age=31536000, immutable"

printf '%s\n' '{"status":"ok","test":"kcsp-web-security-headers","inheritance":true}'
