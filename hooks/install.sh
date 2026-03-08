#!/usr/bin/env bash
set -euo pipefail

TOOL="guardrails"
REPO="thkt/guardrails"
INSTALL_DIR="${HOME}/.local/bin"

detect_platform() {
  local os arch
  os="$(uname -s)"
  arch="$(uname -m)"

  case "$os" in
    Darwin) os="apple-darwin" ;;
    Linux)  os="unknown-linux-gnu" ;;
    MINGW*|MSYS*|CYGWIN*) os="pc-windows-msvc" ;;
    *) echo "Unsupported OS: $os" >&2; exit 1 ;;
  esac

  case "$arch" in
    x86_64|amd64)  arch="x86_64" ;;
    arm64|aarch64) arch="aarch64" ;;
    *) echo "Unsupported architecture: $arch" >&2; exit 1 ;;
  esac

  echo "${arch}-${os}"
}

download() {
  local url="$1" dest="$2"
  if command -v curl &>/dev/null; then
    curl -fsSL "$url" -o "$dest"
  elif command -v wget &>/dev/null; then
    wget -q "$url" -O "$dest"
  else
    echo "Error: curl or wget required" >&2
    exit 1
  fi
}

main() {
  if command -v "$TOOL" &>/dev/null; then
    echo "${TOOL} already installed: $(which "$TOOL")"
    return
  fi

  # Try Homebrew first
  if command -v brew &>/dev/null; then
    echo "Installing ${TOOL} via Homebrew..."
    brew install "thkt/tap/${TOOL}"
    return
  fi

  # Fall back to GitHub Releases
  local platform
  platform="$(detect_platform)"
  local is_windows=false
  [[ "$platform" == *"windows"* ]] && is_windows=true

  local ext="tar.gz"
  local bin_name="$TOOL"
  if $is_windows; then
    ext="zip"
    bin_name="${TOOL}.exe"
  fi

  local asset="${TOOL}-${platform}.${ext}"
  local url="https://github.com/${REPO}/releases/latest/download/${asset}"

  echo "Downloading ${TOOL} for ${platform}..."
  local tmpdir
  tmpdir="$(mktemp -d)"
  trap "rm -rf '$tmpdir'" EXIT

  download "$url" "${tmpdir}/${asset}"

  if $is_windows; then
    unzip -q "${tmpdir}/${asset}" -d "$tmpdir"
  else
    tar xzf "${tmpdir}/${asset}" -C "$tmpdir"
  fi

  mkdir -p "$INSTALL_DIR"
  mv "${tmpdir}/${bin_name}" "${INSTALL_DIR}/${bin_name}"
  $is_windows || chmod +x "${INSTALL_DIR}/${bin_name}"
  echo "Installed ${TOOL} to ${INSTALL_DIR}/${bin_name}"

  if [[ ":$PATH:" != *":${INSTALL_DIR}:"* ]]; then
    echo ""
    echo "Add to your shell profile:"
    echo "  export PATH=\"${INSTALL_DIR}:\$PATH\""
  fi
}

main "$@"
