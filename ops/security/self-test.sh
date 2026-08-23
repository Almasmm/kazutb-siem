#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)

# shellcheck disable=SC1091
. "$SCRIPT_DIR/toolchain.env"

for script in source-scan.sh container-scan.sh build-and-scan.sh self-test.sh; do
  sh -n "$SCRIPT_DIR/$script"
done

for module in \
  "$KCSP_GOVULNCHECK_MODULE" \
  "$KCSP_GOSEC_MODULE" \
  "$KCSP_GITLEAKS_MODULE"; do
  if ! printf '%s\n' "$module" | grep -Eq '@v[0-9]+\.[0-9]+\.[0-9]+$'; then
    printf 'security module is not pinned: %s\n' "$module" >&2
    exit 1
  fi
done

if ! printf '%s\n' "$KCSP_TRIVY_IMAGE" | grep -Eq '^aquasec/trivy@sha256:[0-9a-f]{64}$'; then
  printf 'Trivy image is not pinned by digest: %s\n' "$KCSP_TRIVY_IMAGE" >&2
  exit 1
fi

for dockerfile in \
  Dockerfile.api \
  Dockerfile.dr \
  Dockerfile.haproxy \
  Dockerfile.patroni \
  Dockerfile.pitr-proxy \
  Dockerfile.postgres \
  apps/web/Dockerfile; do
  if ! grep -F "$dockerfile" "$SCRIPT_DIR/build-and-scan.sh" >/dev/null; then
    printf 'runtime image is missing from security build: %s\n' "$dockerfile" >&2
    exit 1
  fi
done

if command -v shellcheck >/dev/null 2>&1; then
  shellcheck -e SC1091,SC2034 "$SCRIPT_DIR"/*.sh
fi

printf '%s\n' 'Security gate policy checks passed.'
