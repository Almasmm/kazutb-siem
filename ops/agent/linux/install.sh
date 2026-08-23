#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage: sudo ./install.sh --config PATH --public-key PATH [options]

Options:
  --config PATH         KCSP agent EnvironmentFile to install.
  --public-key PATH     Trusted PEM public key for manifest verification.
  --allow-unsigned      Permit an unsigned package for an isolated dev test.
  --allow-insecure-http Permit HTTP only when config also opts in explicitly.
  --no-start            Install and enable the service without starting it.
  --help                Show this help.
EOF
}

fail() {
  printf 'install: %s\n' "$*" >&2
  exit 1
}

CONFIG_FILE=""
PUBLIC_KEY=""
ALLOW_UNSIGNED=false
ALLOW_INSECURE_HTTP=false
NO_START=false

while (($# > 0)); do
  case "$1" in
    --config) CONFIG_FILE="${2:-}"; shift 2 ;;
    --public-key) PUBLIC_KEY="${2:-}"; shift 2 ;;
    --allow-unsigned) ALLOW_UNSIGNED=true; shift ;;
    --allow-insecure-http) ALLOW_INSECURE_HTTP=true; shift ;;
    --no-start) NO_START=true; shift ;;
    --help) usage; exit 0 ;;
    *) fail "unknown argument: $1" ;;
  esac
done

[[ ${EUID:-$(id -u)} -eq 0 ]] || fail "root privileges are required"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
CONFIG_TARGET=/etc/kcsp/agent.env
UNIT_TARGET=/etc/systemd/system/kcsp-agent.service
BINARY_TARGET=/opt/kcsp/agent/kcsp-agent

for command_name in awk getent groupadd id install mv sha256sum systemctl useradd usermod; do
  command -v "$command_name" >/dev/null 2>&1 || fail "$command_name is required"
done

for required in README.md agent.env.example install.sh kcsp-agent kcsp-agent.service uninstall.sh manifest.sha256; do
  [[ -f "$SCRIPT_DIR/$required" && ! -L "$SCRIPT_DIR/$required" ]] || fail "package payload is missing or unsafe: $required"
done
if find "$SCRIPT_DIR" -mindepth 1 -maxdepth 1 -type l -print -quit | grep -q .; then
  fail "symbolic links are not permitted in the package"
fi

EXPECTED_MANIFEST=$'README.md\nagent.env.example\ninstall.sh\nkcsp-agent\nkcsp-agent.service\nuninstall.sh'
ACTUAL_MANIFEST="$(awk 'NF == 2 { name=$2; sub(/^\\*/, "", name); print name }' "$SCRIPT_DIR/manifest.sha256")"
[[ "$ACTUAL_MANIFEST" == "$EXPECTED_MANIFEST" ]] || fail "manifest contains an unexpected payload set"
(
  cd -- "$SCRIPT_DIR"
  sha256sum --check --strict --quiet manifest.sha256
) || fail "package checksum verification failed"

if [[ -f "$SCRIPT_DIR/manifest.sha256.sig" && ! -L "$SCRIPT_DIR/manifest.sha256.sig" ]]; then
  [[ -n "$PUBLIC_KEY" && -f "$PUBLIC_KEY" && ! -L "$PUBLIC_KEY" ]] || fail "a trusted --public-key is required for this signed package"
  command -v openssl >/dev/null 2>&1 || fail "openssl is required for signature verification"
  openssl dgst -sha256 -verify "$PUBLIC_KEY" -signature "$SCRIPT_DIR/manifest.sha256.sig" "$SCRIPT_DIR/manifest.sha256" >/dev/null \
    || fail "package signature verification failed"
elif [[ "$ALLOW_UNSIGNED" != true ]]; then
  fail "unsigned package rejected; use a signed release or explicitly pass --allow-unsigned for an isolated dev test"
fi

if [[ -z "$CONFIG_FILE" && -f "$CONFIG_TARGET" && ! -L "$CONFIG_TARGET" ]]; then
  CONFIG_FILE="$CONFIG_TARGET"
fi
[[ -n "$CONFIG_FILE" && -f "$CONFIG_FILE" && ! -L "$CONFIG_FILE" ]] || fail "--config must reference a regular file"
if grep -q $'\r' "$CONFIG_FILE"; then
  fail "config must use Unix line endings"
fi
awk '
  /^[[:space:]]*$/ || /^[[:space:]]*#/ { next }
  !/^KCSP_AGENT_[A-Z0-9_]+=/ { exit 1 }
  {
    key=$0
    sub(/=.*/, "", key)
    if (++seen[key] > 1) { exit 1 }
  }
' "$CONFIG_FILE" || fail "config contains malformed or duplicate keys"

config_value() {
  local key="$1" value
  value="$(awk -v key="$key" 'index($0, key "=") == 1 { print substr($0, length(key) + 2); exit }' "$CONFIG_FILE")"
  if [[ "$value" == \"*\" && "$value" == *\" ]]; then
    value="${value:1:${#value}-2}"
  elif [[ "$value" == \'*\' && "$value" == *\' ]]; then
    value="${value:1:${#value}-2}"
  fi
  printf '%s' "$value"
}

SERVER_URL="$(config_value KCSP_AGENT_SERVER_URL)"
TENANT_ID="$(config_value KCSP_AGENT_TENANT_ID)"
[[ -n "$TENANT_ID" ]] || fail "KCSP_AGENT_TENANT_ID is required"
case "$SERVER_URL" in
  https://?*) ;;
  http://?*)
    [[ "$(config_value KCSP_AGENT_ALLOW_INSECURE_HTTP)" == true && "$ALLOW_INSECURE_HTTP" == true ]] \
      || fail "HTTP requires both KCSP_AGENT_ALLOW_INSECURE_HTTP=true and --allow-insecure-http"
    ;;
  *) fail "KCSP_AGENT_SERVER_URL must be an absolute HTTPS URL" ;;
esac

SOURCE="$(config_value KCSP_AGENT_SOURCE)"
[[ -z "$SOURCE" || "$SOURCE" == auto || "$SOURCE" == journald ]] || fail "Linux package supports only auto or journald source"
ENROLLMENT_TOKEN="$(config_value KCSP_AGENT_ENROLLMENT_TOKEN)"
ACCESS_TOKEN="$(config_value KCSP_AGENT_ACCESS_TOKEN)"
OAUTH_URL="$(config_value KCSP_AGENT_OAUTH_TOKEN_URL)"
if [[ -z "$ENROLLMENT_TOKEN" && -z "$ACCESS_TOKEN" && -z "$OAUTH_URL" && ! -f /var/lib/kcsp-agent/credential.json ]]; then
  fail "initial enrollment token, access token or OAuth configuration is required"
fi
if [[ -n "$OAUTH_URL" ]]; then
  [[ "$OAUTH_URL" == https://?* ]] || fail "KCSP_AGENT_OAUTH_TOKEN_URL must use HTTPS"
  [[ -n "$(config_value KCSP_AGENT_OAUTH_CLIENT_ID)" && -n "$(config_value KCSP_AGENT_OAUTH_CLIENT_SECRET)" ]] \
    || fail "OAuth client ID and secret are required together"
fi

getent group systemd-journal >/dev/null || fail "systemd-journal group is required"
if ! getent group kcsp-agent >/dev/null; then
  groupadd --system kcsp-agent
fi
if ! id kcsp-agent >/dev/null 2>&1; then
  useradd --system --gid kcsp-agent --home-dir /var/lib/kcsp-agent --shell /usr/sbin/nologin kcsp-agent
fi
usermod -g kcsp-agent -a -G systemd-journal kcsp-agent

WAS_ACTIVE=false
if systemctl is-active --quiet kcsp-agent.service; then
  WAS_ACTIVE=true
  systemctl stop kcsp-agent.service
fi
install -d -o root -g root -m 0755 /opt/kcsp/agent /etc/kcsp
install -d -o kcsp-agent -g kcsp-agent -m 0700 /var/lib/kcsp-agent
install -o root -g root -m 0755 "$SCRIPT_DIR/kcsp-agent" "$BINARY_TARGET.new"
mv -f -- "$BINARY_TARGET.new" "$BINARY_TARGET"
install -o root -g root -m 0644 "$SCRIPT_DIR/kcsp-agent.service" "$UNIT_TARGET.new"
mv -f -- "$UNIT_TARGET.new" "$UNIT_TARGET"
install -o root -g root -m 0600 "$CONFIG_FILE" "$CONFIG_TARGET.new"
mv -f -- "$CONFIG_TARGET.new" "$CONFIG_TARGET"
systemctl daemon-reload
systemctl enable kcsp-agent.service >/dev/null

if [[ "$NO_START" != true ]]; then
  systemctl restart kcsp-agent.service
  systemctl is-active --quiet kcsp-agent.service || {
    systemctl status --no-pager kcsp-agent.service >&2 || true
    fail "kcsp-agent.service did not become active"
  }
elif [[ "$WAS_ACTIVE" == true ]]; then
  printf 'install: service was active and remains stopped because --no-start was selected\n' >&2
fi

printf '{"status":"ok","service":"kcsp-agent.service","started":%s,"signature_verified":%s}\n' \
  "$([[ "$NO_START" == true ]] && printf false || printf true)" \
  "$([[ -f "$SCRIPT_DIR/manifest.sha256.sig" ]] && printf true || printf false)"
