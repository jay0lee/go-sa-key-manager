#!/usr/bin/env bash
#
# gcp-sa-key-manager auto-update and install script for macOS and Linux.
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/jay0lee/go-sa-key-manager/main/scripts/update.sh | bash
#   ./scripts/update.sh [--check] [--force] [--version vX.Y.Z] [--target-dir /path]
#

set -euo pipefail

REPO="jay0lee/go-sa-key-manager"
BINARY_NAME="gcp-sa-key-manager"

CHECK_ONLY=false
FORCE=false
TARGET_VERSION=""
TARGET_DIR=""

show_help() {
  cat <<EOF
Usage: update.sh [OPTIONS]

Options:
  -c, --check            Check for updates without downloading or installing
  -f, --force            Force reinstallation even if already at the latest version
  -v, --version <tag>    Install a specific release version (default: latest)
  -t, --target-dir <dir> Specify destination directory for the binary
  -h, --help             Show this help message
EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    -c|--check)
      CHECK_ONLY=true
      shift
      ;;
    -f|--force)
      FORCE=true
      shift
      ;;
    -v|--version)
      TARGET_VERSION="$2"
      shift 2
      ;;
    -t|--target-dir)
      TARGET_DIR="$2"
      shift 2
      ;;
    -h|--help)
      show_help
      exit 0
      ;;
    *)
      echo "Error: Unknown option $1" >&2
      show_help
      exit 1
      ;;
  esac
done

# 1. Detect Operating System
OS_TYPE="$(uname -s)"
case "$OS_TYPE" in
  Darwin)
    OS="darwin"
    ;;
  Linux)
    OS="linux"
    ;;
  *)
    echo "Error: Unsupported operating system '$OS_TYPE'. This script supports macOS and Linux." >&2
    exit 1
    ;;
esac

# 2. Detect CPU Architecture
ARCH_TYPE="$(uname -m)"
case "$ARCH_TYPE" in
  x86_64|amd64)
    ARCH="amd64"
    # Detect Apple Silicon running in Rosetta 2
    if [ "$OS" = "darwin" ]; then
      if [ "$(sysctl -n sysctl.proc_translated 2>/dev/null || echo 0)" = "1" ]; then
        ARCH="arm64"
      else
        echo "Error: Official macOS builds of $BINARY_NAME only support Apple Silicon (ARM64)." >&2
        echo "Intel x86_64 Mac is not supported." >&2
        exit 1
      fi
    fi
    ;;
  arm64|aarch64)
    ARCH="arm64"
    ;;
  *)
    echo "Error: Unsupported architecture '$ARCH_TYPE'. Supported: x86_64/amd64, arm64/aarch64." >&2
    exit 1
    ;;
esac

# 3. Locate Existing Installation & Target Directory
EXISTING_BIN="$(command -v "$BINARY_NAME" 2>/dev/null || true)"
CURRENT_VERSION=""

if [ -n "$EXISTING_BIN" ] && [ -x "$EXISTING_BIN" ]; then
  CURRENT_VERSION="$("$EXISTING_BIN" version 2>/dev/null | grep -E '^gcp-sa-key-manager version' | awk '{print $3}' || true)"
  if [ -z "$TARGET_DIR" ]; then
    TARGET_DIR="$(dirname "$EXISTING_BIN")"
  fi
fi

if [ -z "$TARGET_DIR" ]; then
  if [ -w "/usr/local/bin" ] || [ "$(id -u)" -eq 0 ] || command -v sudo >/dev/null 2>&1; then
    TARGET_DIR="/usr/local/bin"
  else
    TARGET_DIR="$HOME/.local/bin"
  fi
fi

# 4. Determine Target Version
if [ -z "$TARGET_VERSION" ]; then
  echo "Checking for latest release from https://github.com/$REPO..."
  LATEST_RELEASE_JSON="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest")"
  TARGET_VERSION="$(echo "$LATEST_RELEASE_JSON" | grep -E '"tag_name":' | head -n 1 | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')"
  if [ -z "$TARGET_VERSION" ]; then
    echo "Error: Failed to determine latest release version from GitHub API." >&2
    exit 1
  fi
fi

echo "Current version : ${CURRENT_VERSION:-not installed}"
echo "Target version  : $TARGET_VERSION"
echo "Platform        : $OS-$ARCH"
echo "Target path     : $TARGET_DIR/$BINARY_NAME"

# Check if already up-to-date
if [ -n "$CURRENT_VERSION" ] && [ "$CURRENT_VERSION" = "$TARGET_VERSION" ] && [ "$FORCE" = false ]; then
  echo "✓ $BINARY_NAME is already up to date ($CURRENT_VERSION)."
  exit 0
fi

if [ "$CHECK_ONLY" = true ]; then
  if [ "$CURRENT_VERSION" != "$TARGET_VERSION" ]; then
    echo "→ An update is available: $CURRENT_VERSION -> $TARGET_VERSION"
    exit 0
  else
    echo "✓ Up to date."
    exit 0
  fi
fi

# 5. Download Release Archive & Checksums
ARCHIVE_NAME="${BINARY_NAME}-${OS}-${ARCH}.tar.bz2"
BASE_URL="https://github.com/$REPO/releases/download/$TARGET_VERSION"
DOWNLOAD_URL="$BASE_URL/$ARCHIVE_NAME"
CHECKSUMS_URL="$BASE_URL/checksums.txt"

TMPDIR="$(mktemp -d 2>/dev/null || mktemp -d -t 'sakm_update')"
trap 'rm -rf "$TMPDIR"' EXIT

echo "Downloading $ARCHIVE_NAME..."
curl -fsSL "$DOWNLOAD_URL" -o "$TMPDIR/$ARCHIVE_NAME"

echo "Downloading checksums.txt..."
curl -fsSL "$CHECKSUMS_URL" -o "$TMPDIR/checksums.txt"

# 6. Verify SHA256 Checksum
echo "Verifying checksum..."
EXPECTED_SHA="$(grep "$ARCHIVE_NAME" "$TMPDIR/checksums.txt" | awk '{print $1}')"
if [ -z "$EXPECTED_SHA" ]; then
  echo "Error: Archive $ARCHIVE_NAME not found in checksums.txt" >&2
  exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL_SHA="$(sha256sum "$TMPDIR/$ARCHIVE_NAME" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  ACTUAL_SHA="$(shasum -a 256 "$TMPDIR/$ARCHIVE_NAME" | awk '{print $1}')"
else
  echo "Warning: Neither sha256sum nor shasum found; skipping checksum validation."
  ACTUAL_SHA="$EXPECTED_SHA"
fi

if [ "$ACTUAL_SHA" != "$EXPECTED_SHA" ]; then
  echo "Error: Checksum verification failed!" >&2
  echo "  Expected: $EXPECTED_SHA" >&2
  echo "  Actual:   $ACTUAL_SHA" >&2
  exit 1
fi
echo "✓ Checksum verified ($ACTUAL_SHA)"

# 7. Extract Archive
echo "Extracting $ARCHIVE_NAME..."
tar -xjf "$TMPDIR/$ARCHIVE_NAME" -C "$TMPDIR"

EXTRACTED_BIN=""
if [ -f "$TMPDIR/$BINARY_NAME" ]; then
  EXTRACTED_BIN="$TMPDIR/$BINARY_NAME"
elif [ -f "$TMPDIR/${BINARY_NAME}-${OS}-${ARCH}" ]; then
  EXTRACTED_BIN="$TMPDIR/${BINARY_NAME}-${OS}-${ARCH}"
else
  # Check if there is any executable matching gcp-sa-key-manager*
  MATCH="$(find "$TMPDIR" -maxdepth 1 -type f -name "${BINARY_NAME}*" ! -name "*.tar.bz2" ! -name "*.txt" | head -n 1 || true)"
  if [ -n "$MATCH" ]; then
    EXTRACTED_BIN="$MATCH"
  fi
fi

if [ -z "$EXTRACTED_BIN" ] || [ ! -f "$EXTRACTED_BIN" ]; then
  echo "Error: Binary '$BINARY_NAME' not found in extracted archive." >&2
  exit 1
fi
chmod +x "$EXTRACTED_BIN"

# 8. Install Binary
SUDO=""
if [ ! -d "$TARGET_DIR" ]; then
  PARENT="$TARGET_DIR"
  while [ ! -d "$PARENT" ] && [ "$PARENT" != "/" ] && [ "$PARENT" != "." ]; do
    PARENT="$(dirname "$PARENT")"
  done
  if [ ! -w "$PARENT" ]; then
    if command -v sudo >/dev/null 2>&1 && [ "$(id -u)" -ne 0 ]; then
      echo "Escalating privileges via sudo to create $TARGET_DIR..."
      SUDO="sudo"
    else
      echo "Error: Destination parent directory '$PARENT' is not writable and sudo is unavailable." >&2
      exit 1
    fi
  fi
  $SUDO mkdir -p "$TARGET_DIR"
elif [ ! -w "$TARGET_DIR" ]; then
  if command -v sudo >/dev/null 2>&1 && [ "$(id -u)" -ne 0 ]; then
    echo "Escalating privileges via sudo to write to $TARGET_DIR..."
    SUDO="sudo"
  else
    echo "Error: Destination directory '$TARGET_DIR' is not writable and sudo is unavailable." >&2
    exit 1
  fi
fi

echo "Installing to $TARGET_DIR/$BINARY_NAME..."
$SUDO cp -f "$EXTRACTED_BIN" "$TARGET_DIR/$BINARY_NAME"
$SUDO chmod 755 "$TARGET_DIR/$BINARY_NAME"

# 9. Verification
INSTALLED_VER="$("$TARGET_DIR/$BINARY_NAME" version 2>/dev/null | grep -E '^gcp-sa-key-manager version' | awk '{print $3}' || true)"
echo "✓ Successfully installed $BINARY_NAME $INSTALLED_VER"

# 10. Check PATH
case ":$PATH:" in
  *":$TARGET_DIR:"*) ;;
  *)
    echo ""
    echo "Notice: '$TARGET_DIR' is not in your PATH."
    echo "Add it to your profile (e.g. ~/.bashrc or ~/.zshrc):"
    echo "  export PATH=\"$TARGET_DIR:\$PATH\""
    ;;
esac
