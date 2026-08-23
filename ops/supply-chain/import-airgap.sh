#!/usr/bin/env bash
set -Eeuo pipefail

bundle_root="${1:?usage: import-airgap.sh BUNDLE_ROOT TRUSTED_PUBLIC_KEY OFFLINE_REGISTRY [OUTPUT_DIR]}"
trusted_public_key="${2:?usage: import-airgap.sh BUNDLE_ROOT TRUSTED_PUBLIC_KEY OFFLINE_REGISTRY [OUTPUT_DIR]}"
registry="${3:?usage: import-airgap.sh BUNDLE_ROOT TRUSTED_PUBLIC_KEY OFFLINE_REGISTRY [OUTPUT_DIR]}"
output_dir="${4:-$PWD/kcsp-airgap-import}"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
bundle_root="$(cd "$bundle_root" && pwd)"
manifest="$bundle_root/kcsp-airgap-manifest.json"

[[ "$registry" =~ ^[A-Za-z0-9.-]+(:[0-9]+)?(/[a-z0-9._-]+)*$ ]] || {
  echo "offline registry must be a host[:port] with an optional repository prefix and no URL scheme" >&2
  exit 1
}
for command in docker jq; do
  command -v "$command" >/dev/null || { echo "$command is required" >&2; exit 1; }
done

bash "$script_dir/verify-airgap.sh" "$bundle_root" "$trusted_public_key"
mkdir -p "$output_dir"
imports_file="$(mktemp "$output_dir/.kcsp-imports.XXXXXX")"
cleanup() { rm -f -- "$imports_file"; }
trap cleanup EXIT
printf '[]\n' >"$imports_file"
version="$(jq -er '.version' "$manifest")"

while IFS=$'\t' read -r archive local_tag config_digest; do
  docker image load --input "$bundle_root/$archive" >/dev/null
  actual_config="$(docker image inspect --format '{{.Id}}' "$local_tag")"
  [[ "$actual_config" == "$config_digest" ]] || { echo "loaded image config mismatch for $local_tag" >&2; exit 1; }

  while IFS= read -r component; do
    repository="${registry%/}/kcsp-${component}"
    tagged_reference="${repository}:${version}"
    docker image tag "$local_tag" "$tagged_reference"
    docker image push "$tagged_reference" >/dev/null
    pushed_digest="$(docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$tagged_reference" | awk -v prefix="${repository}@" 'index($0,prefix)==1 {sub(prefix,""); print; exit}')"
    [[ "$pushed_digest" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "registry did not return an immutable digest for $component" >&2; exit 1; }
    next="${imports_file}.next"
    jq --arg name "$component" --arg repository "$repository" --arg digest "$pushed_digest" \
      '. + [{name:$name,repository:$repository,digest:$digest}]' "$imports_file" >"$next"
    mv "$next" "$imports_file"
  done < <(jq -r --arg archive "$archive" '.images[] | select(.archive == $archive) | .components[].name' "$manifest")
done < <(jq -r '.images[] | [.archive,.local_tag,.config_digest] | @tsv' "$manifest")

values_path="$output_dir/kcsp-airgap-images.values.yaml"
{
  printf 'global:\n  version: %s\nimages:\n' "$version"
  for component in api collector processor soar-worker ai-worker web; do
    repository="$(jq -er --arg name "$component" '.[] | select(.name == $name) | .repository' "$imports_file")"
    digest="$(jq -er --arg name "$component" '.[] | select(.name == $name) | .digest' "$imports_file")"
    printf '  %s:\n    repository: %s\n    tag: "%s"\n    digest: %s\n    pullPolicy: IfNotPresent\n' "$component" "$repository" "$version" "$digest"
  done
} >"$values_path"

report_path="$output_dir/kcsp-airgap-import-report.json"
jq -n \
  --arg version "$version" \
  --arg registry "$registry" \
  --arg generated "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg values "$values_path" \
  --slurpfile imports "$imports_file" \
  '{schema:"kcsp.airgap-import/v1",version:$version,registry:$registry,generated_at:$generated,passed:true,values_file:$values,images:$imports[0]}' \
  >"$report_path"

printf 'helm_values=%s\nimport_report=%s\n' "$values_path" "$report_path"
