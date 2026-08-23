#!/usr/bin/env bash
set -Eeuo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cosign_image="${KCSP_COSIGN_IMAGE:-ghcr.io/sigstore/cosign/cosign:v3.1.3@sha256:9e5c2f2edc34351160407ca3416c61855bdf9403c3c5936e0f0be7fc261611b8}"
[[ "$cosign_image" == *@sha256:* ]] || { echo "KCSP_COSIGN_IMAGE must be digest pinned" >&2; exit 1; }
for command in docker jq sha256sum tar wc; do
  command -v "$command" >/dev/null || { echo "$command is required" >&2; exit 1; }
done

temporary="$(mktemp -d)"
cleanup() {
  case "$temporary" in
    /tmp/*|/var/tmp/*) rm -rf -- "$temporary" ;;
  esac
}
trap cleanup EXIT
bundle="$temporary/kcsp-airgap-test"
mkdir -p "$bundle/images" "$bundle/chart" "$bundle/release" "$bundle/bin" "$bundle/docs" "$temporary/tar-input"
printf 'image payload\n' >"$temporary/tar-input/manifest.json"
for group in platform web dr; do
  tar -C "$temporary/tar-input" -cf "$bundle/images/$group.tar" manifest.json
done
printf '%s\n' '{"schema":"kcsp.release/v1"}' >"$bundle/release/kcsp-release-manifest.json"
printf '%s\n' '{}' >"$bundle/release/kcsp-release-manifest.sigstore.json"
printf '%s\n' 'test checksum evidence' >"$bundle/release/kcsp-release-manifest.sha256"
cp "$root/ops/supply-chain/offline-signing-config.json" "$bundle/release/offline-signing-config.json"
cp "$root/ops/supply-chain/offline-trusted-root.json" "$bundle/release/offline-trusted-root.json"
printf '%s\n' 'test chart' >"$bundle/chart/kcsp-1.2.3.tgz"
cp "$root/ops/supply-chain/verify-airgap.sh" "$bundle/bin/verify-airgap.sh"
cp "$root/ops/supply-chain/import-airgap.sh" "$bundle/bin/import-airgap.sh"
printf '%s\n' 'test runbook' >"$bundle/docs/airgap-installation.md"

artifacts="$temporary/artifacts.json"
printf '[]\n' >"$artifacts"
for relative_path in \
  images/platform.tar images/web.tar images/dr.tar \
  release/kcsp-release-manifest.json release/kcsp-release-manifest.sigstore.json release/kcsp-release-manifest.sha256 \
  release/offline-signing-config.json \
  release/offline-trusted-root.json \
  chart/kcsp-1.2.3.tgz bin/verify-airgap.sh bin/import-airgap.sh docs/airgap-installation.md; do
  digest="$(sha256sum "$bundle/$relative_path" | awk '{print $1}')"
  size="$(wc -c <"$bundle/$relative_path" | tr -d '[:space:]')"
  next="${artifacts}.next"
  jq --arg path "$relative_path" --arg sha256 "$digest" --argjson size "$size" \
    '. + [{path:$path,kind:"self-test",sha256:$sha256,size_bytes:$size}]' "$artifacts" >"$next"
  mv "$next" "$artifacts"
done

export COSIGN_PASSWORD='kcsp-airgap-self-test-only'
docker run --rm --network none --user 0:0 \
  -e COSIGN_PASSWORD \
  -v "$temporary:/work" \
  -w /work \
  "$cosign_image" generate-key-pair --output-key-prefix /work/kcsp-airgap >/dev/null
public_key_sha256="$(sha256sum "$temporary/kcsp-airgap.pub" | awk '{print $1}')"
release_sha256="$(sha256sum "$bundle/release/kcsp-release-manifest.json" | awk '{print $1}')"
digest64="$(printf '1%.0s' {1..64})"
config64="$(printf '2%.0s' {1..64})"

jq -n \
  --arg public_key_sha256 "$public_key_sha256" \
  --arg release_sha256 "$release_sha256" \
  --arg digest "$digest64" \
  --arg config "$config64" \
  --slurpfile artifacts "$artifacts" \
  '{
    schema:"kcsp.airgap/v1",version:"1.2.3",revision:("a"*40),created_at:"2026-08-23T00:00:00Z",platform:"linux/amd64",
    release_manifest_sha256:$release_sha256,signing_public_key_sha256:$public_key_sha256,
    chart:{path:"chart/kcsp-1.2.3.tgz"},
    images:[
      {group:"platform",archive:"images/platform.tar",local_tag:"kcsp-airgap/platform:1.2.3",config_digest:("sha256:"+$config),components:
        ["api","collector","processor","soar-worker","ai-worker"] | map({name:.,source_reference:("registry.test/kcsp-"+.+"@sha256:"+$digest)})},
      {group:"web",archive:"images/web.tar",local_tag:"kcsp-airgap/web:1.2.3",config_digest:("sha256:"+$config),components:
        [{name:"web",source_reference:("registry.test/kcsp-web@sha256:"+$digest)}]},
      {group:"dr",archive:"images/dr.tar",local_tag:"kcsp-airgap/dr:1.2.3",config_digest:("sha256:"+$config),components:
        [{name:"dr",source_reference:("registry.test/kcsp-dr@sha256:"+$digest)}]}
    ],artifacts:$artifacts[0]
  }' >"$bundle/kcsp-airgap-manifest.json"

docker run --rm --network none --user 0:0 \
  -e COSIGN_PASSWORD \
  -v "$temporary:/keys:ro" \
  -v "$bundle:/work" \
  -w /work \
  "$cosign_image" sign-blob --yes \
  --key /keys/kcsp-airgap.key \
  --signing-config /work/release/offline-signing-config.json \
  --bundle /work/kcsp-airgap-manifest.sigstore.json \
  /work/kcsp-airgap-manifest.json >/dev/null

KCSP_COSIGN_IMAGE="$cosign_image" bash "$root/ops/supply-chain/verify-airgap.sh" "$bundle" "$temporary/kcsp-airgap.pub" >/dev/null
printf 'tampered\n' >>"$bundle/docs/airgap-installation.md"
if KCSP_COSIGN_IMAGE="$cosign_image" bash "$root/ops/supply-chain/verify-airgap.sh" "$bundle" "$temporary/kcsp-airgap.pub" >/dev/null 2>&1; then
  echo "air-gap verifier accepted a modified artifact" >&2
  exit 1
fi

unset COSIGN_PASSWORD
printf '%s\n' '{"status":"ok","test":"kcsp-airgap-offline-tamper","network":"disabled","components":7}'
