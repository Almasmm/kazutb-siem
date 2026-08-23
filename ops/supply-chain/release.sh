#!/usr/bin/env bash
set -Eeuo pipefail

version="${KCSP_RELEASE_VERSION:-${GITHUB_REF_NAME:-}}"
version="${version#v}"
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
  echo "KCSP_RELEASE_VERSION must be a semantic version without a mutable tag" >&2
  exit 1
fi

registry="${KCSP_REGISTRY:-ghcr.io}"
owner="${KCSP_IMAGE_NAMESPACE:-${GITHUB_REPOSITORY_OWNER:-}}"
owner="${owner,,}"
if [[ -z "$owner" ]]; then
  echo "KCSP_IMAGE_NAMESPACE or GITHUB_REPOSITORY_OWNER is required" >&2
  exit 1
fi

revision="${GITHUB_SHA:-$(git rev-parse HEAD)}"
if [[ ! "$revision" =~ ^[0-9a-f]{40}$ ]]; then
  echo "GITHUB_SHA must be a full Git commit SHA" >&2
  exit 1
fi
source_repository="${GITHUB_REPOSITORY:-Almasmm/kazutb-siem}"
source_url="${GITHUB_SERVER_URL:-https://github.com}/${source_repository}"
created="${KCSP_RELEASE_CREATED_AT:-}"
if [[ -z "$created" ]]; then
  created="$(git show -s --format=%cI "$revision")"
fi
sha_tag="sha-${revision:0:12}"
platform="${KCSP_RELEASE_PLATFORM:-linux/amd64}"
output_dir="${KCSP_RELEASE_OUTPUT_DIR:-/tmp/kcsp-release}"

platform_repositories=(
  "$registry/$owner/kcsp-api"
  "$registry/$owner/kcsp-processor"
  "$registry/$owner/kcsp-soar-worker"
  "$registry/$owner/kcsp-ai-worker"
)
web_repository="$registry/$owner/kcsp-web"
dr_repository="$registry/$owner/kcsp-dr"

if [[ "${KCSP_RELEASE_DRY_RUN:-false}" == "true" ]]; then
  printf 'version=%s\nrevision=%s\nplatform=%s\n' "$version" "$revision" "$platform"
  for repository in "${platform_repositories[@]}" "$web_repository" "$dr_repository"; do
    printf 'image=%s:%s\nimage=%s:%s\n' "$repository" "$version" "$repository" "$sha_tag"
  done
  exit 0
fi

for command in docker git jq sha256sum; do
  command -v "$command" >/dev/null || {
    echo "$command is required" >&2
    exit 1
  }
done

cosign_image="${KCSP_COSIGN_IMAGE:?KCSP_COSIGN_IMAGE must pin Cosign by digest}"
if [[ "$cosign_image" != *@sha256:* ]]; then
  echo "KCSP_COSIGN_IMAGE must use an immutable sha256 digest" >&2
  exit 1
fi

mkdir -p "$output_dir"
builder="kcsp-release-${GITHUB_RUN_ID:-$$}"
docker buildx create --name "$builder" --driver docker-container --use >/dev/null
cleanup() {
  docker buildx rm "$builder" >/dev/null 2>&1 || true
}
trap cleanup EXIT

build_group() {
  local group="$1"
  local context="$2"
  local dockerfile="$3"
  local result_variable="$4"
  shift 4
  local repositories=("$@")
  local metadata="$output_dir/${group}-metadata.json"
  local arguments=(
    --file "$dockerfile"
    --platform "$platform"
    --push
    --attest "type=sbom"
    --attest "type=provenance,mode=max"
    --metadata-file "$metadata"
    --label "org.opencontainers.image.created=$created"
    --label "org.opencontainers.image.revision=$revision"
    --label "org.opencontainers.image.source=$source_url"
    --label "org.opencontainers.image.version=$version"
  )
  local repository
  for repository in "${repositories[@]}"; do
    arguments+=(--tag "$repository:$version" --tag "$repository:$sha_tag")
  done
  if [[ -n "${ACTIONS_CACHE_URL:-}" ]]; then
    arguments+=(
      --cache-from "type=gha,scope=kcsp-$group"
      --cache-to "type=gha,scope=kcsp-$group,mode=max"
    )
  fi
  docker buildx build "${arguments[@]}" "$context"
  local digest
  digest="$(jq -er '."containerimage.digest"' "$metadata")"
  if [[ ! "$digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    echo "BuildKit did not return a valid digest for $group" >&2
    exit 1
  fi
  printf -v "$result_variable" '%s' "$digest"
}

platform_digest=""
web_digest=""
dr_digest=""
build_group platform . Dockerfile.api platform_digest "${platform_repositories[@]}"
build_group web apps/web apps/web/Dockerfile web_digest "$web_repository"
build_group dr . Dockerfile.dr dr_digest "$dr_repository"

cosign_environment=()
for variable in \
  ACTIONS_ID_TOKEN_REQUEST_TOKEN \
  ACTIONS_ID_TOKEN_REQUEST_URL \
  GITHUB_ACTIONS \
  GITHUB_REF \
  GITHUB_REPOSITORY \
  GITHUB_SHA \
  GITHUB_WORKFLOW_REF; do
  if [[ -n "${!variable:-}" ]]; then
    cosign_environment+=(-e "$variable")
  fi
done

cosign_image_command() {
  docker run --rm \
    "${cosign_environment[@]}" \
    -e DOCKER_CONFIG=/docker-config \
    -v "$HOME/.docker:/docker-config:ro" \
    "$cosign_image" "$@"
}

sign_reference() {
  local reference="$1"
  cosign_image_command sign --yes \
    -a "git_sha=$revision" \
    -a "version=$version" \
    "$reference"
}

for repository in "${platform_repositories[@]}"; do
  sign_reference "$repository@$platform_digest"
done
sign_reference "$web_repository@$web_digest"
sign_reference "$dr_repository@$dr_digest"

manifest="$output_dir/kcsp-release-manifest.json"
jq -n \
  --arg version "$version" \
  --arg revision "$revision" \
  --arg created "$created" \
  --arg source "$source_url" \
  --arg api "${platform_repositories[0]}@$platform_digest" \
  --arg processor "${platform_repositories[1]}@$platform_digest" \
  --arg soar "${platform_repositories[2]}@$platform_digest" \
  --arg ai "${platform_repositories[3]}@$platform_digest" \
  --arg web "$web_repository@$web_digest" \
  --arg dr "$dr_repository@$dr_digest" \
  '{
    schema: "kcsp.release/v1",
    version: $version,
    revision: $revision,
    created_at: $created,
    source: $source,
    images: [
      {name: "api", reference: $api},
      {name: "processor", reference: $processor},
      {name: "soar-worker", reference: $soar},
      {name: "ai-worker", reference: $ai},
      {name: "web", reference: $web},
      {name: "dr", reference: $dr}
    ]
  }' >"$manifest"

(
  cd "$output_dir"
  sha256sum kcsp-release-manifest.json >kcsp-release-manifest.sha256
)

docker run --rm \
  "${cosign_environment[@]}" \
  -v "$output_dir:/work" \
  -w /work \
  "$cosign_image" sign-blob --yes \
  --bundle /work/kcsp-release-manifest.sigstore.json \
  /work/kcsp-release-manifest.json

printf 'release_manifest=%s\n' "$manifest"
