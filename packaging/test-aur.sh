#!/usr/bin/env bash
# packaging/test-aur.sh — test the PKGBUILD in an Arch Linux Podman container.
#
# Usage:
#   bash packaging/test-aur.sh           # build-only test
#   bash packaging/test-aur.sh --gui     # build + GUI smoke test (needs Xvfb)
#
# Requirements on the host:
#   - podman (Fedora: sudo dnf install podman)
#   - Internet access (pacman db sync, Go modules, Cargo crates)
#
# The container uses archlinux:base-devel. The repo is mounted read-only.
# A non-root "builder" user is created inside the container (makepkg refuses root).
set -euo pipefail

REPO_ROOT=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
PKGVER=$(grep '^pkgver=' "$REPO_ROOT/packaging/PKGBUILD" | cut -d= -f2)
GUI=false
if [[ "${1:-}" == "--gui" ]]; then GUI=true; fi

EXTRA_PKGS=""
if $GUI; then EXTRA_PKGS="xorg-server-xvfb"; fi

# Write the inner container script to a temp file that gets mounted.
INNER=$(mktemp /tmp/aur-container.XXXXXX.sh)
trap "rm -f $INNER" EXIT

cat > "$INNER" << INNER_SCRIPT
#!/usr/bin/env bash
set -euo pipefail

GUI="\${1:-false}"

echo "==> Updating pacman database..."
pacman -Syu --noconfirm

echo "==> Installing build dependencies..."
pacman -S --noconfirm --needed \
    go rust gtk4 libadwaita libcap iproute2 dbus polkit openssl \
    base-devel $EXTRA_PKGS

echo "==> Creating non-root builder user..."
useradd -m builder 2>/dev/null || true

echo "==> Copying PKGBUILD to writable directory..."
cp -r /src/packaging /home/builder/pkg
chown -R builder /home/builder/pkg

echo "==> Packaging local repo as source tarball..."
# Build against the local checkout so Cargo.toml/Cargo.lock changes not yet
# in the GitHub release are picked up.  Mirror the directory structure that
# GitHub's archive endpoint produces (go-openlawsvpn-<ver>/).
ln -sf /src /tmp/go-openlawsvpn-$PKGVER
tar -hczf /home/builder/pkg/openlawsvpn-$PKGVER.tar.gz \
    --exclude-vcs \
    --exclude='go-openlawsvpn-$PKGVER/gui-gtk/target' \
    --exclude='go-openlawsvpn-$PKGVER/rpmbuild' \
    -C /tmp go-openlawsvpn-$PKGVER
rm /tmp/go-openlawsvpn-$PKGVER
# Redirect PKGBUILD source= to use the local tarball.
sed -i "s|^source=.*|source=('openlawsvpn-$PKGVER.tar.gz')|" /home/builder/pkg/PKGBUILD
chown builder /home/builder/pkg/openlawsvpn-$PKGVER.tar.gz

echo "==> Running makepkg..."
# --noconfirm  — non-interactive
# --noprogressbar — quieter output in CI
MAKEPKG_RC=0
su builder -c '
    cd /home/builder/pkg
    HOME=/home/builder \
    GOPATH=/home/builder/go \
    GOFLAGS=-mod=mod \
    makepkg --noconfirm --noprogressbar 2>&1
' || MAKEPKG_RC=\$?

if [ "\$MAKEPKG_RC" -ne 0 ]; then
    echo ""
    echo "==> makepkg FAILED (exit \$MAKEPKG_RC)"
    exit "\$MAKEPKG_RC"
fi

echo "==> Build succeeded. Packages:"
ls /home/builder/pkg/*.pkg.tar.zst 2>/dev/null || ls /home/builder/pkg/*.pkg.tar.xz

if [ "\$GUI" = "true" ]; then
    echo "==> Installing packages for GUI smoke test..."
    pacman -U --noconfirm /home/builder/pkg/openlawsvpn-daemon-*.pkg.tar.* 2>/dev/null || true
    pacman -U --noconfirm /home/builder/pkg/openlawsvpn-cli-*.pkg.tar.* 2>/dev/null || true
    pacman -U --noconfirm /home/builder/pkg/openlawsvpn-gui-*.pkg.tar.* 2>/dev/null || true

    echo "==> Starting D-Bus system daemon..."
    mkdir -p /run/dbus
    dbus-daemon --system --fork 2>/dev/null || true
    sleep 0.5

    echo "==> Starting Xvfb on :99..."
    Xvfb :99 -screen 0 1024x768x24 &
    XVFB_PID=\$!
    sleep 1

    echo "==> Launching GUI smoke test (3 s window)..."
    DISPLAY=:99 openlawsvpn-gui &
    GUI_PID=\$!
    sleep 3

    if kill -0 "\$GUI_PID" 2>/dev/null; then
        kill "\$GUI_PID"
        kill "\$XVFB_PID" 2>/dev/null || true
        echo "PASS: GUI process survived 3 s without crashing"
    else
        kill "\$XVFB_PID" 2>/dev/null || true
        echo "FAIL: GUI exited before 3 s (startup crash?)"
        exit 1
    fi
fi

echo "==> All tests passed"
INNER_SCRIPT

chmod +x "$INNER"

echo "==> Running AUR test in archlinux:base-devel container..."
echo "    GUI smoke test: $GUI"
echo "    Repo: $REPO_ROOT"
echo ""

podman run --rm \
    --network host \
    --security-opt label=disable \
    -v "$REPO_ROOT:/src:ro" \
    -v "$INNER:/run-test.sh:ro" \
    archlinux:base-devel \
    bash /run-test.sh "$GUI"
