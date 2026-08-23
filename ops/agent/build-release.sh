#!/usr/bin/env bash
set -Eeuo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
version="${KCSP_AGENT_RELEASE_VERSION:?KCSP_AGENT_RELEASE_VERSION is required}"
version="${version#v}"
output_dir="${KCSP_AGENT_RELEASE_OUTPUT_DIR:-/tmp/kcsp-agent-release}"
signing_key="${KCSP_AGENT_SIGNING_KEY_FILE:?KCSP_AGENT_SIGNING_KEY_FILE is required}"
trusted_public_key="${KCSP_AGENT_SIGNING_PUBLIC_KEY_FILE:?KCSP_AGENT_SIGNING_PUBLIC_KEY_FILE is required}"

fail() {
  printf 'build-agent-release: %s\n' "$*" >&2
  exit 1
}

[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]] || fail "release version is not semantic"
[[ -f "$signing_key" && ! -L "$signing_key" ]] || fail "agent signing key is missing or unsafe"
[[ -f "$trusted_public_key" && ! -L "$trusted_public_key" ]] || fail "trusted agent public key is missing or unsafe"
for command_name in cmp go mktemp openssl pwsh sha256sum tar; do
  command -v "$command_name" >/dev/null 2>&1 || fail "$command_name is required"
done

mkdir -p -- "$output_dir"
output_dir="$(cd "$output_dir" && pwd -P)"
if find "$output_dir" -mindepth 1 -print -quit | grep -q .; then
  fail "output directory must be empty"
fi

temporary="$(mktemp -d)"
cleanup() {
  case "$temporary" in
    /tmp/*|/var/tmp/*) rm -rf -- "$temporary" ;;
  esac
}
trap cleanup EXIT
mkdir -p "$temporary/bin" "$temporary/verify"

openssl pkey -in "$signing_key" -pubout -out "$temporary/derived.pub" >/dev/null
openssl pkey -pubin -in "$trusted_public_key" -pubout -out "$temporary/trusted.pub" >/dev/null
cmp --silent "$temporary/derived.pub" "$temporary/trusted.pub" || fail "agent private and public signing keys do not match"

linux_packages=()
for architecture in amd64 arm64; do
  binary="$temporary/bin/kcsp-agent-linux-$architecture"
  (
    cd "$root"
    CGO_ENABLED=0 GOOS=linux GOARCH="$architecture" go build \
      -trimpath -ldflags="-s -w -X main.agentVersion=$version" \
      -o "$binary" ./cmd/agent
  )
  bash "$root/ops/agent/linux/self-test.sh" --binary "$binary" >/dev/null
  bash "$root/ops/agent/linux/build-package.sh" \
    --binary "$binary" \
    --version "$version" \
    --arch "$architecture" \
    --output-dir "$output_dir" \
    --signing-key "$signing_key" >/dev/null
  linux_packages+=("kcsp-agent_${version}_linux_${architecture}.tar.gz")
done

windows_binary="$temporary/bin/kcsp-agent-windows-amd64.exe"
(
  cd "$root"
  CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build \
    -trimpath -ldflags="-s -w -X main.agentVersion=$version" \
    -o "$windows_binary" ./cmd/agent
)
pwsh -NoLogo -NoProfile -File "$root/ops/agent/windows/Self-Test.ps1" \
  -PrebuiltBinary "$windows_binary" >/dev/null
pwsh -NoLogo -NoProfile -File "$root/ops/agent/windows/Build-KCSPWindowsPackage.ps1" \
  -Version "$version" \
  -OutputDirectory "$output_dir" \
  -PrebuiltBinary "$windows_binary" >/dev/null
windows_package="kcsp-agent-${version}-windows-amd64.zip"

packages=("${linux_packages[@]}" "$windows_package")
for package in "${packages[@]}"; do
  [[ -f "$output_dir/$package" && ! -L "$output_dir/$package" ]] || fail "release package was not created: $package"
done

(
  cd "$output_dir"
  printf '%s\n' "${packages[@]}" | LC_ALL=C sort | while IFS= read -r package; do
    sha256sum "$package"
  done > kcsp-agent-release-manifest.sha256
)
openssl dgst -sha256 -sign "$signing_key" \
  -out "$output_dir/kcsp-agent-release-manifest.sig" \
  "$output_dir/kcsp-agent-release-manifest.sha256"
install -m 0644 "$temporary/trusted.pub" "$output_dir/kcsp-agent-release.pub"
(
  cd "$output_dir"
  sha256sum kcsp-agent-release.pub > kcsp-agent-release.pub.sha256
  sha256sum --check --strict --quiet kcsp-agent-release-manifest.sha256
  sha256sum --check --strict --quiet kcsp-agent-release.pub.sha256
)
openssl dgst -sha256 -verify "$output_dir/kcsp-agent-release.pub" \
  -signature "$output_dir/kcsp-agent-release-manifest.sig" \
  "$output_dir/kcsp-agent-release-manifest.sha256" >/dev/null \
  || fail "agent release manifest signature verification failed"

for package in "${linux_packages[@]}"; do
  verify_dir="$temporary/verify/${package%.tar.gz}"
  mkdir -p "$verify_dir"
  tar -C "$verify_dir" -xzf "$output_dir/$package"
  package_root="$(find "$verify_dir" -mindepth 1 -maxdepth 1 -type d -print -quit)"
  [[ -n "$package_root" ]] || fail "Linux package has no root directory: $package"
  openssl dgst -sha256 -verify "$output_dir/kcsp-agent-release.pub" \
    -signature "$package_root/manifest.sha256.sig" \
    "$package_root/manifest.sha256" >/dev/null \
    || fail "embedded Linux package signature is invalid: $package"
done

printf '{"status":"ok","version":"%s","packages":3,"linux_architectures":2,"signed":true}\n' "$version"
