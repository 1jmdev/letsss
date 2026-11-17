#!/usr/bin/env bash
# Builds every letsSS artifact on Linux and publishes a GitHub release.
#
# Usage: scripts/release.sh [VERSION]      e.g. scripts/release.sh 0.2.0
set -euo pipefail

repository="1jmdev/letsss"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${root}"

# LNK4099 only reports missing debug symbols of Microsoft's prebuilt C runtime.
export CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS="-C link-arg=/ignore:4099"

step() {
    printf '\n\033[1;36m==> %s\033[0m\n' "$*"
}

run() {
    printf '\033[2m$ %s\033[0m\n' "$*"
    "$@"
}

fail() {
    printf '\033[1;31merror:\033[0m %s\n' "$*" >&2
    exit 1
}

version="${1:-}"
if [ -z "${version}" ]; then
    read -rp "Release version (for example 0.2.0): " version
fi
version="${version#v}"
[[ "${version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "version must look like 1.2.3, got '${version}'"
tag="v${version}"
output="${root}/release/${tag}"

step "Checking tools"
for tool in bun cargo gh git cargo-zigbuild cargo-xwin; do
    command -v "${tool}" >/dev/null || fail "${tool} is not installed"
    printf '  %-15s %s\n' "${tool}" "$(command -v "${tool}")"
done
run gh auth status
if git rev-parse "${tag}" >/dev/null 2>&1; then
    fail "tag ${tag} already exists"
fi
run git status --short

step "Setting version ${version}"
run sed -i "0,/^version = \".*\"/s//version = \"${version}\"/" Cargo.toml
run sed -i "s/^  \"version\": \".*\"/  \"version\": \"${version}\"/" src-tauri/tauri.conf.json
run sed -i "s/^  \"version\": \".*\"/  \"version\": \"${version}\"/" package.json
run cargo update --workspace
run git --no-pager diff --stat

step "Installing frontend dependencies"
run bun install

step "Building Linux desktop app"
run bun tauri build

step "Building Windows desktop app"
run bun tauri build --runner cargo-xwin --target x86_64-pc-windows-msvc --no-bundle

step "Building Linux CLI"
run cargo build --release -p letsss_cli

step "Building Windows CLI"
run cargo zigbuild --release -p letsss_cli --target x86_64-pc-windows-gnu

step "Collecting artifacts in ${output}"
run rm -rf "${output}"
run mkdir -p "${output}"
run cp target/release/letsss "${output}/letsss-linux-x86_64"
run cp target/x86_64-pc-windows-gnu/release/letsss.exe "${output}/letsss-windows-x86_64.exe"
run cp target/x86_64-pc-windows-msvc/release/letsss.exe "${output}/letsSS-desktop-windows-x86_64.exe"
run cp target/release/bundle/appimage/letsSS_"${version}"_amd64.AppImage "${output}/"
run cp target/release/bundle/deb/letsSS_"${version}"_amd64.deb "${output}/"
run cp target/release/bundle/rpm/letsSS-"${version}"-1.x86_64.rpm "${output}/"
(cd "${output}" && sha256sum -- * | tee SHA256SUMS)
run ls -lh "${output}"

step "Ready to publish"
printf '  Repository: %s\n  Tag:        %s\n  Files:      %s\n\n' "${repository}" "${tag}" "${output}"
read -rp "Commit the version change, push ${tag} and publish the release? [y/N] " answer
if [[ ! "${answer}" =~ ^[Yy]$ ]]; then
    printf 'Release cancelled. Artifacts stay in %s; version files remain modified.\n' "${output}"
    exit 0
fi

step "Publishing ${tag}"
run git add Cargo.toml Cargo.lock package.json src-tauri/tauri.conf.json
if git diff --cached --quiet; then
    printf 'Version files are already committed, skipping commit.\n'
else
    run git commit -m "release ${tag}"
fi
run git tag "${tag}"
run git push origin HEAD "${tag}"
run gh release create "${tag}" "${output}"/* \
    --repo "${repository}" \
    --title "letsSS ${tag}" \
    --generate-notes

step "Done: https://github.com/${repository}/releases/tag/${tag}"
