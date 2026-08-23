#!/usr/bin/env bash
set -Eeuo pipefail

manifest="${1:?usage: verify-release.sh MANIFEST [BUNDLE] [CHECKSUM]}"
manifest_dir="$(cd "$(dirname "$manifest")" && pwd)"
manifest_name="$(basename "$manifest")"
bundle="${2:-$manifest_dir/kcsp-release-manifest.sigstore.json}"
checksum="${3:-$manifest_dir/kcsp-release-manifest.sha256}"
bundle_name="$(basename "$bundle")"
checksum_name="$(basename "$checksum")"

for command in docker jq sha256sum; do
  command -v "$command" >/dev/null || {
    echo "$command is required" >&2
    exit 1
  }
done

cosign_image="${KCSP_COSIGN_IMAGE:-ghcr.io/sigstore/cosign/cosign:v3.1.3@sha256:9e5c2f2edc34351160407ca3416c61855bdf9403c3c5936e0f0be7fc261611b8}"
repository="${KCSP_EXPECTED_REPOSITORY:-Almasmm/kazutb-siem}"
issuer="${KCSP_CERTIFICATE_OIDC_ISSUER:-https://token.actions.githubusercontent.com}"
identity="${KCSP_CERTIFICATE_IDENTITY_REGEXP:-^https://github.com/${repository}/.github/workflows/release.yml@refs/tags/v[0-9].*$}"

jq -e '
  .schema == "kcsp.release/v1" and
  (.version | type == "string") and
  (.revision | test("^[0-9a-f]{40}$")) and
  (.images | length == 6) and
  (all(.images[]; .reference | test("@sha256:[0-9a-f]{64}$")))
' "$manifest" >/dev/null

(
  cd "$manifest_dir"
  sha256sum -c "$checksum_name"
)

cosign() {
  docker run --rm \
    -v "$manifest_dir:/work:ro" \
    -w /work \
    "$cosign_image" "$@"
}

while IFS= read -r reference; do
  cosign verify \
    --certificate-identity-regexp "$identity" \
    --certificate-oidc-issuer "$issuer" \
    "$reference" >/dev/null
done < <(jq -r '.images[].reference' "$manifest")

cosign verify-blob \
  --certificate-identity-regexp "$identity" \
  --certificate-oidc-issuer "$issuer" \
  --bundle "/work/$bundle_name" \
  "/work/$manifest_name" >/dev/null

printf '%s\n' '{"status":"ok","verification":"kcsp-release"}'
