#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)

# shellcheck disable=SC1091
. "$SCRIPT_DIR/toolchain.env"

if [ "$#" -eq 0 ]; then
  printf '%s\n' 'usage: container-scan.sh IMAGE [IMAGE...]' >&2
  exit 2
fi

if ! command -v docker >/dev/null 2>&1; then
  printf '%s\n' 'required command is unavailable: docker' >&2
  exit 1
fi

case "$KCSP_TRIVY_IMAGE" in
  *@sha256:*) ;;
  *)
    printf '%s\n' 'KCSP_TRIVY_IMAGE must use an immutable digest' >&2
    exit 1
    ;;
esac

CACHE_VOLUME=kcsp-trivy-cache
docker volume create "$CACHE_VOLUME" >/dev/null

for image in "$@"; do
  printf '==> Container scan: %s\n' "$image"
  docker run --rm \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v "$CACHE_VOLUME:/root/.cache/trivy" \
    "$KCSP_TRIVY_IMAGE" image \
    --scanners vuln,secret \
    --severity HIGH,CRITICAL \
    --ignore-unfixed \
    --exit-code 1 \
    --no-progress \
    --skip-version-check \
    --timeout 10m \
    "$image"
done
