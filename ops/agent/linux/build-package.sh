#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage: build-package.sh --binary PATH --version VERSION --output-dir DIR [options]

Options:
  --arch ARCH          Package architecture: amd64 or arm64.
  --signing-key PATH   PEM private key used to sign manifest.sha256.
  --help               Show this help.
EOF
}

fail() {
  printf 'build-package: %s\n' "$*" >&2
  exit 1
}

BINARY=""
VERSION=""
OUTPUT_DIR=""
ARCH=""
SIGNING_KEY=""

while (($# > 0)); do
  case "$1" in
    --binary) BINARY="${2:-}"; shift 2 ;;
    --version) VERSION="${2:-}"; shift 2 ;;
    --output-dir) OUTPUT_DIR="${2:-}"; shift 2 ;;
    --arch) ARCH="${2:-}"; shift 2 ;;
    --signing-key) SIGNING_KEY="${2:-}"; shift 2 ;;
    --help) usage; exit 0 ;;
    *) fail "unknown argument: $1" ;;
  esac
done

[[ -n "$BINARY" && -f "$BINARY" && ! -L "$BINARY" ]] || fail "--binary must reference a regular file"
[[ -n "$VERSION" && "$VERSION" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || fail "--version contains unsupported characters"
[[ -n "$OUTPUT_DIR" ]] || fail "--output-dir is required"
if [[ -n "$SIGNING_KEY" ]]; then
  [[ -f "$SIGNING_KEY" && ! -L "$SIGNING_KEY" ]] || fail "--signing-key must reference a regular file"
fi

for command_name in install mktemp sha256sum tar; do
  command -v "$command_name" >/dev/null 2>&1 || fail "$command_name is required"
done
if [[ -n "$SIGNING_KEY" ]]; then
  command -v openssl >/dev/null 2>&1 || fail "openssl is required to sign the package"
fi

if [[ -z "$ARCH" ]]; then
  ARCH="$(uname -m)"
fi
case "$ARCH" in
  amd64|x86_64) ARCH=amd64 ;;
  arm64|aarch64) ARCH=arm64 ;;
  *) fail "unsupported architecture: $ARCH" ;;
esac

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PACKAGE_NAME="kcsp-agent_${VERSION}_linux_${ARCH}"
mkdir -p -- "$OUTPUT_DIR"
OUTPUT_DIR="$(cd -- "$OUTPUT_DIR" && pwd -P)"
STAGING="$(mktemp -d)"
trap 'rm -rf -- "$STAGING"' EXIT
PACKAGE_DIR="$STAGING/$PACKAGE_NAME"
mkdir -p -- "$PACKAGE_DIR"

install -m 0755 "$BINARY" "$PACKAGE_DIR/kcsp-agent"
install -m 0644 "$SCRIPT_DIR/kcsp-agent.service" "$PACKAGE_DIR/kcsp-agent.service"
install -m 0600 "$SCRIPT_DIR/agent.env.example" "$PACKAGE_DIR/agent.env.example"
install -m 0755 "$SCRIPT_DIR/install.sh" "$PACKAGE_DIR/install.sh"
install -m 0755 "$SCRIPT_DIR/uninstall.sh" "$PACKAGE_DIR/uninstall.sh"
install -m 0644 "$SCRIPT_DIR/README.md" "$PACKAGE_DIR/README.md"

(
  cd -- "$PACKAGE_DIR"
  for file in README.md agent.env.example install.sh kcsp-agent kcsp-agent.service uninstall.sh; do
    sha256sum "$file"
  done > manifest.sha256
)
chmod 0644 "$PACKAGE_DIR/manifest.sha256"

if [[ -n "$SIGNING_KEY" ]]; then
  openssl dgst -sha256 -sign "$SIGNING_KEY" -out "$PACKAGE_DIR/manifest.sha256.sig" "$PACKAGE_DIR/manifest.sha256"
  chmod 0644 "$PACKAGE_DIR/manifest.sha256.sig"
fi

ARCHIVE="$OUTPUT_DIR/$PACKAGE_NAME.tar.gz"
tar -C "$STAGING" -czf "$ARCHIVE" "$PACKAGE_NAME"
(
  cd -- "$OUTPUT_DIR"
  sha256sum "$(basename -- "$ARCHIVE")" > "$(basename -- "$ARCHIVE").sha256"
)
printf '{"status":"ok","package":"%s","signed":%s,"arch":"%s"}\n' \
  "$ARCHIVE" "$([[ -n "$SIGNING_KEY" ]] && printf true || printf false)" "$ARCH"
