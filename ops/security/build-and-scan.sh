#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH='' cd -- "$SCRIPT_DIR/../.." && pwd)

API_IMAGE=kcsp-security-api:scan
DR_IMAGE=kcsp-security-dr:scan
HAPROXY_IMAGE=kcsp-security-haproxy:scan
PATRONI_IMAGE=kcsp-security-patroni:scan
PITR_PROXY_IMAGE=kcsp-security-pitr-proxy:scan
POSTGRES_IMAGE=kcsp-postgres:17
WEB_IMAGE=kcsp-security-web:scan

build_image() {
  image=$1
  dockerfile=$2
  context=$3

  printf '==> Build security candidate: %s\n' "$image"
  docker build --file "$dockerfile" --tag "$image" "$context"
}

if ! command -v docker >/dev/null 2>&1; then
  printf '%s\n' 'required command is unavailable: docker' >&2
  exit 1
fi

build_image "$API_IMAGE" "$ROOT_DIR/Dockerfile.api" "$ROOT_DIR"
build_image "$DR_IMAGE" "$ROOT_DIR/Dockerfile.dr" "$ROOT_DIR"
build_image "$HAPROXY_IMAGE" "$ROOT_DIR/Dockerfile.haproxy" "$ROOT_DIR"
build_image "$POSTGRES_IMAGE" "$ROOT_DIR/Dockerfile.postgres" "$ROOT_DIR"
build_image "$PATRONI_IMAGE" "$ROOT_DIR/Dockerfile.patroni" "$ROOT_DIR"
build_image "$PITR_PROXY_IMAGE" "$ROOT_DIR/Dockerfile.pitr-proxy" "$ROOT_DIR"
build_image "$WEB_IMAGE" "$ROOT_DIR/apps/web/Dockerfile" "$ROOT_DIR/apps/web"

sh "$SCRIPT_DIR/container-scan.sh" \
  "$API_IMAGE" \
  "$DR_IMAGE" \
  "$HAPROXY_IMAGE" \
  "$POSTGRES_IMAGE" \
  "$PATRONI_IMAGE" \
  "$PITR_PROXY_IMAGE" \
  "$WEB_IMAGE"
