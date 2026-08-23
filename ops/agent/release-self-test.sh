#!/usr/bin/env bash
set -Eeuo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
for command_name in go mktemp openssl pwsh sha256sum; do
  command -v "$command_name" >/dev/null 2>&1 || { echo "$command_name is required" >&2; exit 1; }
done

temporary="$(mktemp -d)"
cleanup() {
  case "$temporary" in
    /tmp/*|/var/tmp/*) rm -rf -- "$temporary" ;;
  esac
}
trap cleanup EXIT
mkdir -p "$temporary/output"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$temporary/release.key" >/dev/null 2>&1
openssl pkey -in "$temporary/release.key" -pubout -out "$temporary/release.pub" >/dev/null 2>&1

KCSP_AGENT_RELEASE_VERSION=1.2.3-self-test \
KCSP_AGENT_RELEASE_OUTPUT_DIR="$temporary/output" \
KCSP_AGENT_SIGNING_KEY_FILE="$temporary/release.key" \
KCSP_AGENT_SIGNING_PUBLIC_KEY_FILE="$temporary/release.pub" \
  bash "$root/ops/agent/build-release.sh" >/dev/null

(
  cd "$temporary/output"
  sha256sum --check --strict --quiet kcsp-agent-release-manifest.sha256
  sha256sum --check --strict --quiet kcsp-agent-release.pub.sha256
)
openssl dgst -sha256 -verify "$temporary/output/kcsp-agent-release.pub" \
  -signature "$temporary/output/kcsp-agent-release-manifest.sig" \
  "$temporary/output/kcsp-agent-release-manifest.sha256" >/dev/null

tampered="$temporary/output/kcsp-agent-1.2.3-self-test-windows-amd64.zip"
printf 'tampered\n' >>"$tampered"
if (cd "$temporary/output" && sha256sum --check --strict --quiet kcsp-agent-release-manifest.sha256) >/dev/null 2>&1; then
  echo "agent release verifier accepted a modified package" >&2
  exit 1
fi

printf '%s\n' '{"status":"ok","test":"kcsp-agent-release-tamper","packages":3}'
