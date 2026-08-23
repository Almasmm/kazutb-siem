#!/usr/bin/env bash
set -Eeuo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
release_script="$root/ops/supply-chain/release.sh"
verify_script="$root/ops/supply-chain/verify-release.sh"
airgap_build_script="$root/ops/supply-chain/build-airgap.sh"
airgap_verify_script="$root/ops/supply-chain/verify-airgap.sh"
airgap_import_script="$root/ops/supply-chain/import-airgap.sh"
airgap_self_test="$root/ops/supply-chain/airgap-self-test.sh"
plan="$(mktemp)"
airgap_plan="$(mktemp)"
fake_manifest="$(mktemp)"
trap 'rm -f "$plan" "$airgap_plan" "$fake_manifest"' EXIT

bash -n "$release_script"
bash -n "$verify_script"
bash -n "$airgap_build_script"
bash -n "$airgap_verify_script"
bash -n "$airgap_import_script"
bash -n "$airgap_self_test"

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

jq -n '
  def ref($name;$digest): {name:$name,reference:("ghcr.io/almasmm/kcsp-"+$name+"@sha256:"+$digest)};
  {schema:"kcsp.release/v1",version:"1.2.3",revision:"0123456789abcdef0123456789abcdef01234567",created_at:"2026-08-23T00:00:00Z",source:"https://github.com/Almasmm/kazutb-siem",
   images:[ref("api";("1"*64)),ref("collector";("1"*64)),ref("processor";("1"*64)),ref("soar-worker";("1"*64)),ref("ai-worker";("1"*64)),ref("web";("2"*64)),ref("dr";("3"*64))]}
' >"$fake_manifest"
KCSP_AIRGAP_DRY_RUN=true bash "$airgap_build_script" "$fake_manifest" >"$airgap_plan"
grep -q 'archive=platform components=api,collector,processor,soar-worker,ai-worker digest=sha256:' "$airgap_plan"
grep -q 'archive=web components=web digest=sha256:' "$airgap_plan"
grep -q 'archive=dr components=dr digest=sha256:' "$airgap_plan"

jq '(.images[] | select(.name == "collector") | .reference) = "ghcr.io/almasmm/kcsp-collector@sha256:" + ("4"*64)' "$fake_manifest" >"${fake_manifest}.bad"
if KCSP_AIRGAP_DRY_RUN=true bash "$airgap_build_script" "${fake_manifest}.bad" >/dev/null 2>&1; then
  echo "air-gap policy accepted divergent platform digests" >&2
  exit 1
fi
rm -f "${fake_manifest}.bad"

printf '%s\n' '{"status":"ok","test":"kcsp-supply-chain-self-test","images":7,"airgap_archives":3}'
