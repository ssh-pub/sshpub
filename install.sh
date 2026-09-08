#!/bin/sh
set -eu

PROJECT="sshpub"
VERSION="${SSHPUB_VERSION:-latest}"
INSTALL_DIR="${SSHPUB_INSTALL_DIR:-/usr/local/bin}"
DOWNLOAD_BASE="${SSHPUB_DOWNLOAD_BASE:-https://sshpub.com/download}"

fail() {
  printf '%s\n' "Error: $*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "$1 is required"
}

detect_os() {
  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  case "$os" in
    linux) printf '%s\n' linux ;;
    darwin) printf '%s\n' darwin ;;
    *) fail "unsupported operating system: $os" ;;
  esac
}

detect_arch() {
  arch="$(uname -m)"
  case "$arch" in
    x86_64 | amd64) printf '%s\n' amd64 ;;
    arm64 | aarch64) printf '%s\n' arm64 ;;
    armv7l | armv7) printf '%s\n' armv7 ;;
    *) fail "unsupported CPU architecture: $arch" ;;
  esac
}

download() {
  label="$1"
  url="$2"
  dest="$3"
  show_progress="$4"
  if [ -n "$label" ]; then
    printf '%s\n' "$label" >&2
  fi

  if command -v curl >/dev/null 2>&1; then
    if [ "$show_progress" = "1" ] && [ -t 2 ]; then
      curl -fL -# "$url" -o "$dest"
    else
      curl -fsSL "$url" -o "$dest"
    fi
    return
  fi
  if command -v wget >/dev/null 2>&1; then
    wget -q "$url" -O "$dest"
    return
  fi
  fail "curl or wget is required"
}

checksum_hash() {
  file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    set -- $(sha256sum "$file")
    printf '%s\n' "$1"
    return
  fi
  if command -v shasum >/dev/null 2>&1; then
    set -- $(shasum -a 256 "$file")
    printf '%s\n' "$1"
    return
  fi
  fail "sha256sum or shasum is required"
}

expected_checksum() {
  file="$1"
  asset="$2"
  while read -r hash name rest; do
    if [ "$name" = "$asset" ]; then
      printf '%s\n' "$hash"
      return
    fi
  done < "$file"
  fail "checksum for $asset not found"
}

verify_checksum() {
  file="$1"
  asset="$2"
  checksums="$3"
  expected="$(expected_checksum "$checksums" "$asset" | tr '[:upper:]' '[:lower:]')"
  actual="$(checksum_hash "$file" | tr '[:upper:]' '[:lower:]')"
  printf '%s' "Verifying checksum... " >&2
  [ "$expected" = "$actual" ] || {
    printf '\n' >&2
    fail "checksum verification failed for $asset"
  }
  printf '%s\n' "OK" >&2
}

sudo_run() {
  need_cmd sudo
  sudo "$@"
}

install_file() {
  src="$1"
  dest="$2"
  dir="$(dirname "$dest")"
  tmp="$dir/.sshpub.tmp.$$"

  if [ "$(id -u)" -eq 0 ]; then
    mkdir -p "$dir"
    trap 'rm -f "$tmp"; rm -rf "$tmpdir"' EXIT INT TERM
    cp "$src" "$tmp"
    chmod 0755 "$tmp"
    mv "$tmp" "$dest"
    return
  fi

  if [ -d "$dir" ] && [ -w "$dir" ]; then
    trap 'rm -f "$tmp"; rm -rf "$tmpdir"' EXIT INT TERM
    cp "$src" "$tmp"
    chmod 0755 "$tmp"
    mv "$tmp" "$dest"
    return
  fi

  sudo_run mkdir -p "$dir"
  trap 'sudo -n rm -f "$tmp" >/dev/null 2>&1 || true; rm -rf "$tmpdir"' EXIT INT TERM
  sudo_run cp "$src" "$tmp"
  sudo_run chmod 0755 "$tmp"
  sudo_run mv "$tmp" "$dest"
}

main() {
  need_cmd uname
  need_cmd tr
  need_cmd mktemp
  need_cmd dirname

  os="$(detect_os)"
  arch="$(detect_arch)"
  asset="${PROJECT}-${os}-${arch}"

  download_base="${DOWNLOAD_BASE%/}"
  if [ "$VERSION" = "latest" ]; then
    url="${download_base}/cli/${asset}"
    checksums_url="${download_base}/cli/checksums.txt"
  else
    url="${download_base}/cli/${VERSION}/${asset}"
    checksums_url="${download_base}/cli/${VERSION}/checksums.txt"
  fi

  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' EXIT INT TERM

  bin="$tmpdir/$PROJECT"
  checksums="$tmpdir/checksums.txt"
  download "Downloading $PROJECT $VERSION ($os/$arch)..." "$url" "$bin" 1
  download "" "$checksums_url" "$checksums" 0
  verify_checksum "$bin" "$asset" "$checksums"
  chmod 0755 "$bin"

  install_file "$bin" "$INSTALL_DIR/$PROJECT"

  printf '%s\n' "Installed $PROJECT to $INSTALL_DIR/$PROJECT"
  printf '\n'
  "$INSTALL_DIR/$PROJECT" version
}

main "$@"
