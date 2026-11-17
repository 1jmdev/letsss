#!/usr/bin/env bash
# Downloads the latest letsSS command-line release and runs it as root.
set -euo pipefail

repository="1jmdev/letsss"
asset="letsss-linux-x86_64"
destination="$(mktemp -d)/letsss"

echo "Downloading letsSS..."
curl -fsSL "https://github.com/${repository}/releases/latest/download/${asset}" -o "${destination}"
chmod +x "${destination}"

echo "Starting letsSS (root is required for memory inspection)..."
if [ "$(id -u)" -eq 0 ]; then
    "${destination}" --no-pause "$@"
else
    sudo "${destination}" --no-pause "$@"
fi
