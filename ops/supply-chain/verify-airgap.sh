#!/usr/bin/env bash
set -Eeuo pipefail

bundle_root="${1:?usage: verify-airgap.sh EXTRACTED_BUNDLE_ROOT TRUSTED_PUBLIC_KEY}"
trusted_public_key="${2:?usage: verify-airgap.sh EXTRACTED_BUNDLE_ROOT TRUSTED_PUBLIC_KEY}"
bundle_root="$(cd "$bundle_root" && pwd)"
trusted_public_key="$(cd "$(dirname "$trusted_public_key")" && pwd)/$(basename "$trusted_public_key")"
manifest="$bundle_root/kcsp-airgap-manifest.json"
signature_bundle="$bundle_root/kcsp-airgap-manifest.sigstore.json"

for command in docker jq sha256sum tar openssl find grep; do
  command -v "$command" >/dev/null || { echo "$command is required" >&2; exit 1; }
done
for file in "$manifest" "$signature_bundle" "$trusted_public_key"; do
  [[ -f "$file" ]] || { echo "required air-gap verification file is missing" >&2; exit 1; }
done
if find "$bundle_root" -type l -print -quit | grep -q .; then
  echo "symbolic links are not permitted in an air-gap bundle" >&2
  exit 1
fi

jq -e '
  .schema == "kcsp.airgap/v1" and
  (.version | test("^[0-9]+\\.[0-9]+\\.[0-9]+([.-][0-9A-Za-z.-]+)?$")) and
  (.revision | test("^[0-9a-f]{40}$")) and
  (.platform | test("^linux/(amd64|arm64)$")) and
  (.release_manifest_sha256 | test("^[0-9a-f]{64}$")) and
  (.signing_public_key_sha256 | test("^[0-9a-f]{64}$")) and
  (.images | length == 3) and
  ([.images[].components[].name] | sort == ["ai-worker","api","collector","dr","processor","soar-worker","web"]) and
  (all(.images[];
    (.archive | test("^[A-Za-z0-9._/-]+$")) and
    (.archive | startswith("images/")) and
    (.local_tag | test("^kcsp-airgap/[a-z0-9._-]+:[A-Za-z0-9._-]+$")) and
    (.config_digest | test("^sha256:[0-9a-f]{64}$")) and
    (all(.components[]; .source_reference | test("^[^[:space:]]+@sha256:[0-9a-f]{64}$"))))) and
  (.artifacts | length >= 10) and
  ([.artifacts[].path] | length == (unique | length)) and
  (all(.artifacts[];
    (.path | test("^[A-Za-z0-9._/-]+$")) and
    (.path | startswith("/") | not) and
    (.path | contains("..") | not) and
    (.sha256 | test("^[0-9a-f]{64}$")) and
    (.size_bytes | type == "number" and . >= 0)))
' "$manifest" >/dev/null

expected_key_sha256="$(jq -er '.signing_public_key_sha256' "$manifest")"
actual_key_sha256="$(sha256sum "$trusted_public_key" | awk '{print $1}')"
[[ "$actual_key_sha256" == "$expected_key_sha256" ]] || { echo "trusted air-gap public key fingerprint mismatch" >&2; exit 1; }

while IFS=$'\t' read -r relative_path expected_sha expected_size; do
  absolute_path="$bundle_root/$relative_path"
  [[ -f "$absolute_path" ]] || { echo "bundle artifact is missing: $relative_path" >&2; exit 1; }
  actual_sha="$(sha256sum "$absolute_path" | awk '{print $1}')"
  actual_size="$(wc -c <"$absolute_path" | tr -d '[:space:]')"
  [[ "$actual_sha" == "$expected_sha" && "$actual_size" == "$expected_size" ]] || {
    echo "bundle artifact integrity failed: $relative_path" >&2
    exit 1
  }
done < <(jq -r '.artifacts[] | [.path,.sha256,(.size_bytes|tostring)] | @tsv' "$manifest")

agent_dir="$bundle_root/agents"
if [[ -d "$agent_dir" ]]; then
  version="$(jq -er '.version' "$manifest")"
  expected_agent_manifest="$(printf '%s\n' \
    "kcsp-agent-${version}-windows-amd64.zip" \
    "kcsp-agent_${version}_linux_amd64.tar.gz" \
    "kcsp-agent_${version}_linux_arm64.tar.gz" | LC_ALL=C sort)"
  actual_agent_manifest="$(awk 'NF == 2 { name=$2; sub(/^\\*/, "", name); print name }' \
    "$agent_dir/kcsp-agent-release-manifest.sha256" | LC_ALL=C sort)"
  [[ "$actual_agent_manifest" == "$expected_agent_manifest" ]] || { echo "embedded agent manifest has an unexpected package set" >&2; exit 1; }
  expected_agent_files="$(printf '%s\n' \
    "kcsp-agent-${version}-windows-amd64.zip" \
    "kcsp-agent_${version}_linux_amd64.tar.gz" \
    "kcsp-agent_${version}_linux_amd64.tar.gz.sha256" \
    "kcsp-agent_${version}_linux_arm64.tar.gz" \
    "kcsp-agent_${version}_linux_arm64.tar.gz.sha256" \
    kcsp-agent-release-manifest.sha256 \
    kcsp-agent-release-manifest.sig \
    kcsp-agent-release.pub \
    kcsp-agent-release.pub.sha256 | LC_ALL=C sort)"
  actual_agent_files="$(find "$agent_dir" -mindepth 1 -maxdepth 1 -type f -printf '%f\n' | LC_ALL=C sort)"
  [[ "$actual_agent_files" == "$expected_agent_files" ]] || { echo "air-gap agent directory contains unexpected files" >&2; exit 1; }
  (
    cd "$agent_dir"
    sha256sum --check --strict --quiet kcsp-agent-release-manifest.sha256
    sha256sum --check --strict --quiet kcsp-agent-release.pub.sha256
    sha256sum --check --strict --quiet "kcsp-agent_${version}_linux_amd64.tar.gz.sha256"
    sha256sum --check --strict --quiet "kcsp-agent_${version}_linux_arm64.tar.gz.sha256"
  ) || { echo "embedded agent checksum verification failed" >&2; exit 1; }
  openssl dgst -sha256 -verify "$agent_dir/kcsp-agent-release.pub" \
    -signature "$agent_dir/kcsp-agent-release-manifest.sig" \
    "$agent_dir/kcsp-agent-release-manifest.sha256" >/dev/null \
    || { echo "embedded agent release signature is invalid" >&2; exit 1; }
fi

while IFS= read -r archive; do
  while IFS= read -r entry; do
    [[ "$entry" != /* && "$entry" != *"../"* && "$entry" != ".." ]] || {
      echo "unsafe path in image archive: $archive" >&2
      exit 1
    }
  done < <(tar -tf "$bundle_root/$archive")
done < <(jq -r '.images[].archive' "$manifest")

release_sha="$(sha256sum "$bundle_root/release/kcsp-release-manifest.json" | awk '{print $1}')"
[[ "$release_sha" == "$(jq -er '.release_manifest_sha256' "$manifest")" ]] || {
  echo "embedded release manifest does not match the air-gap manifest" >&2
  exit 1
}
jq -e '.mediaType == "application/vnd.dev.sigstore.signingconfig.v0.2+json" and .rekorTlogConfig == {} and .tsaConfig == {}' \
  "$bundle_root/release/offline-signing-config.json" >/dev/null
jq -e '.mediaType == "application/vnd.dev.sigstore.trustedroot+json;version=0.1" and (keys | length == 1)' \
  "$bundle_root/release/offline-trusted-root.json" >/dev/null

cosign_image="${KCSP_COSIGN_IMAGE:-ghcr.io/sigstore/cosign/cosign:v3.1.3@sha256:9e5c2f2edc34351160407ca3416c61855bdf9403c3c5936e0f0be7fc261611b8}"
[[ "$cosign_image" == *@sha256:* ]] || { echo "KCSP_COSIGN_IMAGE must be digest pinned" >&2; exit 1; }
docker run --rm --network none --user 0:0 --cap-drop ALL --security-opt no-new-privileges \
  -v "$bundle_root:/work:ro" \
  -v "$trusted_public_key:/trust/kcsp-airgap.pub:ro" \
  -w /work \
  "$cosign_image" verify-blob \
  --key /trust/kcsp-airgap.pub \
  --bundle /work/kcsp-airgap-manifest.sigstore.json \
  --trusted-root /work/release/offline-trusted-root.json \
  --insecure-ignore-tlog \
  /work/kcsp-airgap-manifest.json >/dev/null

printf '%s\n' '{"status":"ok","verification":"kcsp-airgap","network":"disabled"}'
