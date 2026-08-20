#!/usr/bin/env bash
# Verify that all authoritative package versions agree.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

spec_version="$(sed -n 's/^Version:[[:space:]]*//p' "$ROOT/packaging/openlawsvpn.spec")"
cargo_version="$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$ROOT/gui-gtk/Cargo.toml" | head -1)"
pkgbuild_version="$(sed -n 's/^pkgver=//p' "$ROOT/packaging/PKGBUILD")"

expected="$spec_version"
failed=0

check_version() {
    local source="$1"
    local actual="$2"

    if [[ -z "$actual" ]]; then
        echo "ERROR: could not read version from $source" >&2
        failed=1
    elif [[ "$actual" != "$expected" ]]; then
        echo "ERROR: $source has $actual; expected $expected" >&2
        failed=1
    fi
}

check_version "gui-gtk/Cargo.toml" "$cargo_version"
check_version "packaging/PKGBUILD" "$pkgbuild_version"

if (( failed != 0 )); then
    echo "Run scripts/bump-version.sh <X.Y.Z> and commit the complete bump." >&2
    exit 1
fi

echo "Version check passed: $expected"

release_tag="${1:-}"
if [[ -n "$release_tag" && "$release_tag" != "v$expected" ]]; then
    echo "ERROR: release tag $release_tag does not match package version v$expected" >&2
    exit 1
fi

if [[ -n "$release_tag" ]]; then
    echo "Release tag check passed: $release_tag"
fi
