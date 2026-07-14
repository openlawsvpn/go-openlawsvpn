#!/usr/bin/env bash
# Usage: scripts/bump-version.sh <new-version>
# Updates all in-tree version strings. Does NOT commit or tag.
set -euo pipefail

VERSION="${1:-}"
if [[ -z "$VERSION" ]]; then
    echo "Usage: $0 <new-version>  (e.g. 1.2.0)" >&2
    exit 1
fi

ROOT="$(git rev-parse --show-toplevel)"

sed -i "s/^Version:        .*/Version:        $VERSION/" "$ROOT/packaging/openlawsvpn.spec"
sed -i "s/^version = \".*\"/version = \"$VERSION\"/" "$ROOT/gui-gtk/Cargo.toml"
sed -i "s/^pkgver=.*/pkgver=$VERSION/" "$ROOT/packaging/PKGBUILD"
sed -i "s/Current tag: \*\*v[0-9.]*\*\*/Current tag: **v$VERSION**/" "$ROOT/CLAUDE.md"

echo "Bumped to $VERSION in:"
echo "  packaging/openlawsvpn.spec"
echo "  gui-gtk/Cargo.toml"
echo "  packaging/PKGBUILD"
echo "  CLAUDE.md"
echo ""
echo "Remember to:"
echo "  1. Add %changelog entry in packaging/openlawsvpn.spec"
echo "  2. Update sha256sums in packaging/PKGBUILD after building the pkg tag tarball"
