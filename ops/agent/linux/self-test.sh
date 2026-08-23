#!/usr/bin/env bash
set -Eeuo pipefail

fail() {
  printf 'self-test: %s\n' "$*" >&2
  exit 1
}

BINARY=""
while (($# > 0)); do
  case "$1" in
    --binary) BINARY="${2:-}"; shift 2 ;;
    --help) printf 'Usage: self-test.sh --binary PATH\n'; exit 0 ;;
    *) fail "unknown argument: $1" ;;
  esac
done

[[ -n "$BINARY" && -f "$BINARY" && ! -L "$BINARY" ]] || fail "--binary must reference a real Linux agent binary"
for command_name in bash cmp grep mktemp openssl sha256sum tar; do
  command -v "$command_name" >/dev/null 2>&1 || fail "$command_name is required"
done

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
for script in build-package.sh install.sh self-test.sh uninstall.sh; do
  bash -n "$SCRIPT_DIR/$script"
done

for directive in \
  'User=kcsp-agent' \
  'SupplementaryGroups=systemd-journal' \
  'EnvironmentFile=/etc/kcsp/agent.env' \
  'NoNewPrivileges=true' \
  'ProtectSystem=strict' \
  'ProtectHome=true' \
  'ProtectKernelTunables=true' \
  'ProtectKernelModules=true' \
  'CapabilityBoundingSet=' \
  'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6' \
  'StateDirectoryMode=0700'; do
  grep -Fqx "$directive" "$SCRIPT_DIR/kcsp-agent.service" || fail "missing systemd hardening directive: $directive"
done

WORK="$(mktemp -d)"
trap 'rm -rf -- "$WORK"' EXIT
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$WORK/signing-key.pem" >/dev/null 2>&1
openssl pkey -in "$WORK/signing-key.pem" -pubout -out "$WORK/signing-public.pem" >/dev/null 2>&1
mkdir -p -- "$WORK/output" "$WORK/extracted"
"$SCRIPT_DIR/build-package.sh" \
  --binary "$BINARY" \
  --version 0.5.0-self-test \
  --output-dir "$WORK/output" \
  --signing-key "$WORK/signing-key.pem" >/dev/null

ARCHIVE="$(find "$WORK/output" -maxdepth 1 -type f -name '*.tar.gz' -print -quit)"
[[ -n "$ARCHIVE" && -f "$ARCHIVE.sha256" ]] || fail "build did not produce the archive and external checksum"
(
  cd -- "$WORK/output"
  sha256sum --check --strict --quiet "$(basename -- "$ARCHIVE").sha256"
) || fail "external package checksum is invalid"
tar -C "$WORK/extracted" -xzf "$ARCHIVE"
PACKAGE_DIR="$(find "$WORK/extracted" -mindepth 1 -maxdepth 1 -type d -print -quit)"
[[ -n "$PACKAGE_DIR" ]] || fail "archive does not contain a package directory"
(
  cd -- "$PACKAGE_DIR"
  sha256sum --check --strict --quiet manifest.sha256
) || fail "payload checksum is invalid"
openssl dgst -sha256 -verify "$WORK/signing-public.pem" \
  -signature "$PACKAGE_DIR/manifest.sha256.sig" "$PACKAGE_DIR/manifest.sha256" >/dev/null \
  || fail "manifest signature is invalid"
cmp --silent "$BINARY" "$PACKAGE_DIR/kcsp-agent" || fail "packaged agent differs from the input binary"

if grep -Eq 'kcsp_agent_[A-Za-z0-9]{16}|BEGIN (RSA |EC )?PRIVATE KEY' "$PACKAGE_DIR/agent.env.example"; then
  fail "example configuration contains secret material"
fi

printf '{"status":"ok","platform":"linux","signed_package":true,"systemd_hardening":true}\n'
