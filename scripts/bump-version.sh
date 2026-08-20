#!/usr/bin/env bash
# Usage: scripts/bump-version.sh <new-version>
# Updates all in-tree version strings. Does NOT commit or tag.
set -euo pipefail

VERSION="${1:-}"
if [[ -z "$VERSION" ]]; then
    echo "Usage: $0 <new-version>  (e.g. 1.2.0)" >&2
    exit 1
fi

if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Version must use X.Y.Z format (for example, 1.2.1)" >&2
    exit 1
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

sed -i "s/^Version:        .*/Version:        $VERSION/" "$ROOT/packaging/openlawsvpn.spec"
sed -i "s/^version = \".*\"/version = \"$VERSION\"/" "$ROOT/gui-gtk/Cargo.toml"
sed -i "s/^pkgver=.*/pkgver=$VERSION/" "$ROOT/packaging/PKGBUILD"

echo "Bumped to $VERSION in:"
echo "  packaging/openlawsvpn.spec"
echo "  gui-gtk/Cargo.toml"
echo "  packaging/PKGBUILD"
echo ""
bash "$ROOT/scripts/check-version.sh"
echo ""
echo "Remember to:"
echo "  1. Move CHANGELOG.md Unreleased entries to version $VERSION"
echo "  2. Add %changelog entry in packaging/openlawsvpn.spec"
echo "  3. Update sha256sums in packaging/PKGBUILD after building the pkg tag tarball"
