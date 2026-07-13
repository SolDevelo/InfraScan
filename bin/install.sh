#!/usr/bin/env bash
set -euo pipefail

REPO_RAW_URL="https://raw.githubusercontent.com/SolDevelo/InfraScan/main/bin/infrascan"
INSTALL_DIR="${INFRASCAN_INSTALL_DIR:-/usr/local/bin}"
BIN_NAME="infrascan"

echo "Installing InfraScan Docker CLI"

if ! command -v docker >/dev/null 2>&1; then
  echo "Error: Docker is required but was not found on the PATH." >&2
  echo "Install Docker first: https://docs.docker.com/engine/install/" >&2
  exit 1
fi

echo "Docker found: $(docker --version)"

TMP_FILE="$(mktemp)"
trap 'rm -f "$TMP_FILE"' EXIT

echo "Downloading ${BIN_NAME} from ${REPO_RAW_URL}..."
if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$REPO_RAW_URL" -o "$TMP_FILE"
elif command -v wget >/dev/null 2>&1; then
  wget -q "$REPO_RAW_URL" -O "$TMP_FILE"
else
  echo "Error: curl or wget is required to download ${BIN_NAME}." >&2
  exit 1
fi

DEST="${INSTALL_DIR}/${BIN_NAME}"

if [ -w "$INSTALL_DIR" ]; then
  install -m 0755 "$TMP_FILE" "$DEST"
  chmod +x "$DEST"
else
  echo "Elevated permissions required to write to ${INSTALL_DIR}."
  sudo install -m 0755 "$TMP_FILE" "$DEST"
  sudo chmod +x "$DEST"
fi

echo "InfraScan CLI installed to ${DEST}"
echo "Run 'infrascan --help' to get started."
