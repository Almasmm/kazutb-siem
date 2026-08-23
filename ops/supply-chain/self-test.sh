#!/usr/bin/env bash
set -Eeuo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
release_script="$root/ops/supply-chain/release.sh"
verify_script="$root/ops/supply-chain/verify-release.sh"
plan="$(mktemp)"
trap 'rm -f "$plan"' EXIT

bash -n "$release_script"
bash -n "$verify_script"

KCSP_RELEASE_DRY_RUN=true \
KCSP_RELEASE_VERSION=1.2.3 \
KCSP_RELEASE_CREATED_AT=2026-08-23T00:00:00Z \
KCSP_IMAGE_NAMESPACE=Almasmm \
GITHUB_REPOSITORY=Almasmm/kazutb-siem \
GITHUB_REPOSITORY_OWNER=Almasmm \
GITHUB_SHA=0123456789abcdef0123456789abcdef01234567 \
GITHUB_SERVER_URL=https://github.com \
bash "$release_script" >"$plan"

for image in api processor soar-worker ai-worker web dr; do
  grep -q "ghcr.io/almasmm/kcsp-$image:1.2.3" "$plan"
  grep -q "ghcr.io/almasmm/kcsp-$image:sha-0123456789ab" "$plan"
done
if grep -q ':latest' "$plan"; then
  echo "release plan contains a mutable latest tag" >&2
  exit 1
fi
if KCSP_RELEASE_DRY_RUN=true \
  KCSP_RELEASE_VERSION=latest \
  KCSP_RELEASE_CREATED_AT=2026-08-23T00:00:00Z \
  KCSP_IMAGE_NAMESPACE=Almasmm \
  GITHUB_SHA=0123456789abcdef0123456789abcdef01234567 \
  bash "$release_script" >/dev/null 2>&1; then
  echo "release policy accepted a non-semantic version" >&2
  exit 1
fi

printf '%s\n' '{"status":"ok","test":"kcsp-supply-chain-self-test","images":6}'
