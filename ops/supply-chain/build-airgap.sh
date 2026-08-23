#!/usr/bin/env bash
set -Eeuo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
manifest="${1:?usage: build-airgap.sh RELEASE_MANIFEST [SIGSTORE_BUNDLE] [CHECKSUM]}"
manifest_dir="$(cd "$(dirname "$manifest")" && pwd)"
manifest="${manifest_dir}/$(basename "$manifest")"
sigstore_bundle="${2:-$manifest_dir/kcsp-release-manifest.sigstore.json}"
release_checksum="${3:-$manifest_dir/kcsp-release-manifest.sha256}"
agent_release_dir="${4:-${KCSP_AGENT_RELEASE_DIR:-}}"

command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }

jq -e '
  .schema == "kcsp.release/v1" and
  (.version | test("^[0-9]+\\.[0-9]+\\.[0-9]+([.-][0-9A-Za-z.-]+)?$")) and
  (.revision | test("^[0-9a-f]{40}$")) and
  ([.images[].name] | sort == ["ai-worker","api","collector","dr","processor","soar-worker","web"]) and
  (.images | length == 7) and
  (all(.images[]; .reference | test("^[^[:space:]]+@sha256:[0-9a-f]{64}$")))
' "$manifest" >/dev/null

image_reference() {
  jq -er --arg name "$1" '.images[] | select(.name == $name) | .reference' "$manifest"
}

version="$(jq -er '.version' "$manifest")"
revision="$(jq -er '.revision' "$manifest")"
created="${KCSP_AIRGAP_CREATED_AT:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
platform="${KCSP_AIRGAP_PLATFORM:-linux/amd64}"
platform_slug="${platform//\//-}"
output_dir="${KCSP_AIRGAP_OUTPUT_DIR:-/tmp/kcsp-airgap}"

platform_digest=""
for component in api collector processor soar-worker ai-worker; do
  reference="$(image_reference "$component")"
  digest="${reference##*@}"
  if [[ -z "$platform_digest" ]]; then
    platform_digest="$digest"
  elif [[ "$digest" != "$platform_digest" ]]; then
    echo "platform image components do not share one immutable digest" >&2
    exit 1
  fi
done

if [[ "${KCSP_AIRGAP_DRY_RUN:-false}" == "true" ]]; then
  printf 'schema=kcsp.airgap-plan/v1\nversion=%s\nrevision=%s\nplatform=%s\n' "$version" "$revision" "$platform"
  printf 'archive=platform components=api,collector,processor,soar-worker,ai-worker digest=%s\n' "$platform_digest"
  for component in web dr; do
    reference="$(image_reference "$component")"
    printf 'archive=%s components=%s digest=%s\n' "$component" "$component" "${reference##*@}"
  done
  exit 0
fi

for command in docker sha256sum tar gzip date wc openssl find grep; do
  command -v "$command" >/dev/null || { echo "$command is required" >&2; exit 1; }
done
for file in "$sigstore_bundle" "$release_checksum"; do
  [[ -f "$file" ]] || { echo "release evidence is missing: $file" >&2; exit 1; }
done

signing_key="${KCSP_AIRGAP_SIGNING_KEY_FILE:?KCSP_AIRGAP_SIGNING_KEY_FILE is required}"
trusted_public_key="${KCSP_AIRGAP_PUBLIC_KEY_FILE:?KCSP_AIRGAP_PUBLIC_KEY_FILE is required}"
[[ -f "$signing_key" ]] || { echo "air-gap signing key file is missing" >&2; exit 1; }
[[ -f "$trusted_public_key" ]] || { echo "air-gap public key file is missing" >&2; exit 1; }
cosign_image="${KCSP_COSIGN_IMAGE:-ghcr.io/sigstore/cosign/cosign:v3.1.3@sha256:9e5c2f2edc34351160407ca3416c61855bdf9403c3c5936e0f0be7fc261611b8}"
helm_image="${KCSP_HELM_IMAGE:-alpine/helm:3.17.3@sha256:d899e6316789fec04ee95300a18e454b7942539cbb3d89bde3e0655d6ca2e895}"
[[ "$cosign_image" == *@sha256:* ]] || { echo "KCSP_COSIGN_IMAGE must be digest pinned" >&2; exit 1; }
[[ "$helm_image" == *@sha256:* ]] || { echo "KCSP_HELM_IMAGE must be digest pinned" >&2; exit 1; }

bash "$root/ops/supply-chain/verify-release.sh" "$manifest" "$sigstore_bundle" "$release_checksum"

agent_assets=()
if [[ -n "$agent_release_dir" ]]; then
  agent_release_dir="$(cd "$agent_release_dir" && pwd)"
  agent_trusted_public_key="${KCSP_AGENT_TRUSTED_PUBLIC_KEY_FILE:?KCSP_AGENT_TRUSTED_PUBLIC_KEY_FILE is required when agent assets are included}"
  [[ -f "$agent_trusted_public_key" && ! -L "$agent_trusted_public_key" ]] || { echo "trusted agent public key is missing or unsafe" >&2; exit 1; }
  expected_agent_manifest="$(printf '%s\n' \
    "kcsp-agent-${version}-windows-amd64.zip" \
    "kcsp-agent_${version}_linux_amd64.tar.gz" \
    "kcsp-agent_${version}_linux_arm64.tar.gz" | LC_ALL=C sort)"
  actual_agent_manifest="$(awk 'NF == 2 { name=$2; sub(/^\\*/, "", name); print name }' \
    "$agent_release_dir/kcsp-agent-release-manifest.sha256" | LC_ALL=C sort)"
  [[ "$actual_agent_manifest" == "$expected_agent_manifest" ]] || { echo "agent release manifest has an unexpected package set" >&2; exit 1; }
  agent_assets=(
    "kcsp-agent-${version}-windows-amd64.zip"
    "kcsp-agent_${version}_linux_amd64.tar.gz"
    "kcsp-agent_${version}_linux_amd64.tar.gz.sha256"
    "kcsp-agent_${version}_linux_arm64.tar.gz"
    "kcsp-agent_${version}_linux_arm64.tar.gz.sha256"
    "kcsp-agent-release-manifest.sha256"
    "kcsp-agent-release-manifest.sig"
    "kcsp-agent-release.pub"
    "kcsp-agent-release.pub.sha256"
  )
  for asset in "${agent_assets[@]}"; do
    [[ -f "$agent_release_dir/$asset" && ! -L "$agent_release_dir/$asset" ]] || { echo "agent release asset is missing or unsafe: $asset" >&2; exit 1; }
  done
  (
    cd "$agent_release_dir"
    sha256sum --check --strict --quiet kcsp-agent-release-manifest.sha256
    sha256sum --check --strict --quiet kcsp-agent-release.pub.sha256
    sha256sum --check --strict --quiet "kcsp-agent_${version}_linux_amd64.tar.gz.sha256"
    sha256sum --check --strict --quiet "kcsp-agent_${version}_linux_arm64.tar.gz.sha256"
  )
  trusted_agent_fingerprint="$(openssl pkey -pubin -in "$agent_trusted_public_key" -outform DER | sha256sum | awk '{print $1}')"
  release_agent_fingerprint="$(openssl pkey -pubin -in "$agent_release_dir/kcsp-agent-release.pub" -outform DER | sha256sum | awk '{print $1}')"
  [[ "$trusted_agent_fingerprint" == "$release_agent_fingerprint" ]] || { echo "agent release public key does not match the offline trust anchor" >&2; exit 1; }
  openssl dgst -sha256 -verify "$agent_trusted_public_key" \
    -signature "$agent_release_dir/kcsp-agent-release-manifest.sig" \
    "$agent_release_dir/kcsp-agent-release-manifest.sha256" >/dev/null \
    || { echo "agent release manifest signature is invalid" >&2; exit 1; }
fi

mkdir -p "$output_dir"
temporary="$(mktemp -d "$output_dir/.kcsp-airgap-build.XXXXXX")"
cleanup() {
  case "$temporary" in
    "$output_dir"/.kcsp-airgap-build.*) rm -rf -- "$temporary" ;;
  esac
}
trap cleanup EXIT

bundle_name="kcsp-airgap-${version}-${platform_slug}"
bundle_root="$temporary/$bundle_name"
mkdir -p "$bundle_root/images" "$bundle_root/chart" "$bundle_root/release" "$bundle_root/bin" "$bundle_root/docs"
if ((${#agent_assets[@]} > 0)); then
  mkdir -p "$bundle_root/agents"
fi
cp "$manifest" "$bundle_root/release/kcsp-release-manifest.json"
cp "$sigstore_bundle" "$bundle_root/release/kcsp-release-manifest.sigstore.json"
cp "$release_checksum" "$bundle_root/release/kcsp-release-manifest.sha256"
cp "$root/ops/supply-chain/offline-signing-config.json" "$bundle_root/release/offline-signing-config.json"
cp "$root/ops/supply-chain/offline-trusted-root.json" "$bundle_root/release/offline-trusted-root.json"
cp "$root/ops/supply-chain/verify-airgap.sh" "$bundle_root/bin/verify-airgap.sh"
cp "$root/ops/supply-chain/import-airgap.sh" "$bundle_root/bin/import-airgap.sh"
cp "$root/docs/runbooks/airgap-installation.md" "$bundle_root/docs/airgap-installation.md"
chmod 0755 "$bundle_root/bin/verify-airgap.sh" "$bundle_root/bin/import-airgap.sh"

artifacts_file="$temporary/artifacts.json"
images_file="$temporary/images.json"
printf '[]\n' >"$artifacts_file"
printf '[]\n' >"$images_file"

add_artifact() {
  local relative_path="$1"
  local kind="$2"
  local absolute_path="$bundle_root/$relative_path"
  local digest size next
  digest="$(sha256sum "$absolute_path" | awk '{print $1}')"
  size="$(wc -c <"$absolute_path" | tr -d '[:space:]')"
  next="$temporary/artifacts.next.json"
  jq --arg path "$relative_path" --arg kind "$kind" --arg sha256 "$digest" --argjson size "$size" \
    '. + [{path:$path,kind:$kind,sha256:$sha256,size_bytes:$size}]' "$artifacts_file" >"$next"
  mv "$next" "$artifacts_file"
}

build_image_archive() {
  local group="$1"
  local source_component="$2"
  shift 2
  local components=("$@")
  local source_reference local_tag archive_path config_digest component_json next component reference
  source_reference="$(image_reference "$source_component")"
  local_tag="kcsp-airgap/${group}:${version}"
  archive_path="images/${group}.tar"

  docker pull --platform "$platform" "$source_reference" >/dev/null
  config_digest="$(docker image inspect --format '{{.Id}}' "$source_reference")"
  [[ "$config_digest" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "invalid image config digest for $group" >&2; exit 1; }
  docker image tag "$source_reference" "$local_tag"
  docker image save --output "$bundle_root/$archive_path" "$local_tag"
  add_artifact "$archive_path" image-archive

  component_json='[]'
  for component in "${components[@]}"; do
    reference="$(image_reference "$component")"
    component_json="$(jq -cn --argjson current "$component_json" --arg name "$component" --arg source "$reference" '$current + [{name:$name,source_reference:$source}]')"
  done
  next="$temporary/images.next.json"
  jq --arg group "$group" --arg archive "$archive_path" --arg local_tag "$local_tag" \
    --arg config_digest "$config_digest" --argjson components "$component_json" \
    '. + [{group:$group,archive:$archive,local_tag:$local_tag,config_digest:$config_digest,components:$components}]' \
    "$images_file" >"$next"
  mv "$next" "$images_file"
}

build_image_archive platform api api collector processor soar-worker ai-worker
build_image_archive web web web
build_image_archive dr dr dr

docker run --rm \
  -v "$root:/src:ro" \
  -v "$bundle_root/chart:/out" \
  -w /src \
  "$helm_image" package deploy/helm/kcsp --destination /out --version "$version" --app-version "$version" >/dev/null
chart_path="chart/kcsp-${version}.tgz"
[[ -f "$bundle_root/$chart_path" ]] || { echo "Helm chart package was not created" >&2; exit 1; }

for item in \
  "release/kcsp-release-manifest.json:release-manifest" \
  "release/kcsp-release-manifest.sigstore.json:release-signature" \
  "release/kcsp-release-manifest.sha256:release-checksum" \
  "release/offline-signing-config.json:offline-signing-policy" \
  "release/offline-trusted-root.json:offline-trusted-root" \
  "$chart_path:helm-chart" \
  "bin/verify-airgap.sh:verification-tool" \
  "bin/import-airgap.sh:import-tool" \
  "docs/airgap-installation.md:runbook"; do
  add_artifact "${item%%:*}" "${item##*:}"
done

for asset in "${agent_assets[@]}"; do
  cp "$agent_release_dir/$asset" "$bundle_root/agents/$asset"
  case "$asset" in
    *.tar.gz|*.zip) artifact_kind=agent-package ;;
    *.sig) artifact_kind=agent-release-signature ;;
    *.pub|*.pub.sha256) artifact_kind=agent-trust-evidence ;;
    *) artifact_kind=agent-release-evidence ;;
  esac
  add_artifact "agents/$asset" "$artifact_kind"
done

public_key_sha256="$(sha256sum "$trusted_public_key" | awk '{print $1}')"
release_manifest_sha256="$(sha256sum "$manifest" | awk '{print $1}')"
airgap_manifest="$bundle_root/kcsp-airgap-manifest.json"
jq -n \
  --arg version "$version" \
  --arg revision "$revision" \
  --arg created "$created" \
  --arg platform "$platform" \
  --arg release_manifest_sha256 "$release_manifest_sha256" \
  --arg signing_key_sha256 "$public_key_sha256" \
  --arg chart "$chart_path" \
  --slurpfile artifacts "$artifacts_file" \
  --slurpfile images "$images_file" \
  '{
    schema:"kcsp.airgap/v1",version:$version,revision:$revision,created_at:$created,platform:$platform,
    release_manifest_sha256:$release_manifest_sha256,signing_public_key_sha256:$signing_key_sha256,
    chart:{path:$chart},images:$images[0],artifacts:$artifacts[0]
  }' >"$airgap_manifest"

signing_key="$(cd "$(dirname "$signing_key")" && pwd)/$(basename "$signing_key")"
cosign_environment=()
if [[ -n "${COSIGN_PASSWORD:-}" ]]; then
  cosign_environment+=(-e COSIGN_PASSWORD)
fi
docker run --rm --network none --user 0:0 --cap-drop ALL --security-opt no-new-privileges \
  "${cosign_environment[@]}" \
  -v "$bundle_root:/work" \
  -v "$signing_key:/keys/signing.key:ro" \
  -w /work \
  "$cosign_image" sign-blob --yes \
  --key /keys/signing.key \
  --signing-config /work/release/offline-signing-config.json \
  --bundle /work/kcsp-airgap-manifest.sigstore.json \
  /work/kcsp-airgap-manifest.json >/dev/null

archive="$output_dir/${bundle_name}.tar.gz"
epoch="$(date -u -d "$created" +%s)"
tar --sort=name --mtime="@$epoch" --clamp-mtime --owner=0 --group=0 --numeric-owner \
  -C "$temporary" -cf - "$bundle_name" | gzip -n >"$archive"
sha256sum "$archive" >"${archive}.sha256"

printf 'airgap_bundle=%s\nairgap_checksum=%s\n' "$archive" "${archive}.sha256"
