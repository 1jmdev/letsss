#!/usr/bin/env bash
# Downloads the latest letsSS release and runs the desktop app or the command-line tool.
set -euo pipefail

repository="1jmdev/letsss"

printf '\n  \033[1;36mletsSS - Minecraft screenshare tool\033[0m\n\n'
printf '  1) Desktop app\n  2) Command-line tool\n  3) Exit\n\n'
choice=""
until [[ "${choice}" =~ ^[123]$ ]]; do
    read -rp "Select 1, 2 or 3: " choice < /dev/tty
done

case "${choice}" in
    1) asset="letsSS-desktop-linux-x86_64" ;;
    2) asset="letsss-linux-x86_64" ;;
    3) exit 0 ;;
esac

destination="$(mktemp -d)/${asset}"
echo "Downloading ${asset}..."
curl -fL "https://github.com/${repository}/releases/latest/download/${asset}" -o "${destination}"
chmod +x "${destination}"

echo "Starting letsSS (root is required for memory inspection)..."
if [ "${choice}" = "1" ]; then
    sudo -E "${destination}" < /dev/tty
else
    sudo "${destination}" --no-pause < /dev/tty
fi
