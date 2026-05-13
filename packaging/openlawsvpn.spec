# SPDX-License-Identifier: LGPL-2.1-or-later
%global debug_package %{nil}
Name:           openlawsvpn
Version:        1.0.5
Release:        1%{?dist}
Summary:        AWS Client VPN client with SAML/SSO support — pure Go stack

# Source (daemon + protocol engine): LGPL-2.1-or-later
# GUI binary (statically links Rust crates): LGPL-2.1-or-later AND MIT AND Apache-2.0 AND BSD-2-Clause
SourceLicense:  LGPL-2.1-or-later
License:        LGPL-2.1-or-later

URL:            https://github.com/openlawsvpn/go-openlawsvpn
Source0:        {{{ git_repo_pack }}}

# Tests are not shipped in the source tree — disable check bcond.
%bcond check 0

BuildRequires:  golang >= 1.21
BuildRequires:  cargo-rpm-macros
BuildRequires:  systemd-rpm-macros

%description
AWS Client VPN client with full SAML/SSO support.
Pure Go protocol engine (go-openlawsvpn) with a GTK4 GUI.
No OpenVPN Inc runtime required.

# ── Subpackages ───────────────────────────────────────────────────────────────

%package daemon
Summary:        openlawsvpn VPN daemon (D-Bus system service)
License:        LGPL-2.1-or-later
Requires:       dbus
Requires:       polkit
%{?systemd_requires}

%description daemon
Background daemon that manages the VPN tunnel via go-openlawsvpn.
Runs as a systemd system service under the openlawsvpn user with CAP_NET_ADMIN.
Exposes com.openlawsvpn.Daemon on the system bus.

%package cli
Summary:        openlawsvpn CLI
License:        LGPL-2.1-or-later
Requires:       iproute

%description cli
Headless command-line VPN client for openlawsvpn.
Supports direct SAML/CRV1 mode and relay mode (-relay <token>).
Requires CAP_NET_ADMIN — run with sudo or set file capability.

%package gui
Summary:        openlawsvpn GTK4 GUI
# GUI binary statically links Rust crates — full license conjunction required.
License:        LGPL-2.1-or-later AND MIT AND Apache-2.0 AND BSD-2-Clause
Requires:       openlawsvpn-daemon = %{version}-%{release}
Requires:       gtk4
Requires:       libadwaita
Requires:       dbus

%description gui
GTK4 + libadwaita desktop client for openlawsvpn.
Communicates with openlawsvpn-daemon via D-Bus.
Includes system-tray support via StatusNotifierItem.

# ── Prep ──────────────────────────────────────────────────────────────────────

%prep
%setup -T -b 0 -q -n go-openlawsvpn
cd gui-gtk && %cargo_prep && cd -

# ── Dynamic BuildRequires ─────────────────────────────────────────────────────

%generate_buildrequires
cd gui-gtk && %cargo_generate_buildrequires && cd -

# ── Build ─────────────────────────────────────────────────────────────────────

%build
CGO_ENABLED=0 go build -o %{_builddir}/openlawsvpn-daemon ./cmd/daemon
CGO_ENABLED=0 go build -o %{_builddir}/openlawsvpn-cli ./cmd/cli

cd gui-gtk
%cargo_build
# Generate license breakdown for statically linked crates (required by guidelines).
%{cargo_license_summary}
%{cargo_license} > LICENSE.dependencies
cd -

# ── Install ───────────────────────────────────────────────────────────────────

%install
install -Dm755 %{_builddir}/openlawsvpn-daemon \
    %{buildroot}%{_libexecdir}/openlawsvpn-daemon

install -Dm644 cmd/daemon/openlawsvpn-daemon.service \
    %{buildroot}%{_unitdir}/openlawsvpn-daemon.service

install -Dm644 packaging/10-openlawsvpn-dns.rules \
    %{buildroot}%{_datadir}/polkit-1/rules.d/10-openlawsvpn-dns.rules

# System bus: policy and activation files.
install -Dm644 packaging/com.openlawsvpn.Daemon.conf \
    %{buildroot}%{_datadir}/dbus-1/system.d/com.openlawsvpn.Daemon.conf

install -Dm644 packaging/com.openlawsvpn.Daemon.service \
    %{buildroot}%{_datadir}/dbus-1/system-services/com.openlawsvpn.Daemon.service

install -Dm644 packaging/90-openlawsvpn.preset \
    %{buildroot}%{_presetdir}/90-openlawsvpn.preset

install -Dm755 %{_builddir}/openlawsvpn-cli \
    %{buildroot}%{_bindir}/openlawsvpn-cli

# Install GUI binary directly from target/rpm/ (non-crate project — do not use %%cargo_install).
install -Dm755 gui-gtk/target/rpm/openlawsvpn-gui \
    %{buildroot}%{_bindir}/openlawsvpn-gui

install -Dm644 packaging/openlawsvpn-gui.desktop \
    %{buildroot}%{_datadir}/applications/openlawsvpn-gui.desktop

install -Dm644 gui-gtk/resources/icons/vpn-disconnected.svg \
    %{buildroot}%{_datadir}/icons/hicolor/scalable/apps/openlawsvpn-disconnected.svg

install -Dm644 gui-gtk/resources/icons/vpn-connected.svg \
    %{buildroot}%{_datadir}/icons/hicolor/scalable/apps/openlawsvpn-connected.svg

install -Dm644 gui-gtk/resources/icons/com.openlawsvpn.gui.svg \
    %{buildroot}%{_datadir}/icons/hicolor/scalable/apps/com.openlawsvpn.gui.svg

# ── Check ─────────────────────────────────────────────────────────────────────

%if %{with check}
%check
cd gui-gtk && %cargo_test && cd -
%endif

# ── Pre/post user management ─────────────────────────────────────────────────

%pre daemon
getent group openlawsvpn  >/dev/null || groupadd -r openlawsvpn
getent passwd openlawsvpn >/dev/null || \
    useradd -r -g openlawsvpn -s /sbin/nologin \
            -d /var/lib/openlawsvpn \
            -c "openlawsvpn VPN daemon" openlawsvpn
# Add each active human user to the openlawsvpn group so they can call the daemon.
for u in $(getent passwd | awk -F: '$3>=1000 && $3<65534 {print $1}'); do
    usermod -aG openlawsvpn "$u" 2>/dev/null || true
done
exit 0

# ── Files ─────────────────────────────────────────────────────────────────────

%files cli
%license LICENSE LICENSE_USAGE_EXCEPTION
%{_bindir}/openlawsvpn-cli

%files daemon
%license LICENSE LICENSE_USAGE_EXCEPTION
%caps(cap_net_admin=eip) %{_libexecdir}/openlawsvpn-daemon
%{_unitdir}/openlawsvpn-daemon.service
%{_datadir}/dbus-1/system.d/com.openlawsvpn.Daemon.conf
%{_datadir}/dbus-1/system-services/com.openlawsvpn.Daemon.service
%{_datadir}/polkit-1/rules.d/10-openlawsvpn-dns.rules
%{_presetdir}/90-openlawsvpn.preset

%files gui
%license gui-gtk/LICENSE.dependencies
%{_bindir}/openlawsvpn-gui
%{_datadir}/applications/openlawsvpn-gui.desktop
%{_datadir}/icons/hicolor/scalable/apps/openlawsvpn-disconnected.svg
%{_datadir}/icons/hicolor/scalable/apps/openlawsvpn-connected.svg
%{_datadir}/icons/hicolor/scalable/apps/com.openlawsvpn.gui.svg

# ── Scriptlets ────────────────────────────────────────────────────────────────

%post gui
%{?ldconfig_scriptlet}
gtk-update-icon-cache -f -t %{_datadir}/icons/hicolor &>/dev/null || :
update-desktop-database %{_datadir}/applications &>/dev/null || :

%postun gui
gtk-update-icon-cache -f -t %{_datadir}/icons/hicolor &>/dev/null || :
update-desktop-database %{_datadir}/applications &>/dev/null || :

%post daemon
%systemd_post openlawsvpn-daemon.service

%preun daemon
%systemd_preun openlawsvpn-daemon.service

%postun daemon
%systemd_postun_with_restart openlawsvpn-daemon.service

# ── Changelog ─────────────────────────────────────────────────────────────────

%changelog
* Tue May 13 2026 Anatolii Vorona <vorona.tolik@gmail.com> - 1.0.5-1
- fix(client): use net.JoinHostPort for IPv6 endpoint construction (PR#2)
  Replaces fmt.Sprintf("%s:%d") which produced invalid addresses for IPv6
  literals causing "too many colons in address" dial errors

* Thu May  7 2026 Anatolii Vorona <vorona.tolik@gmail.com> - 1.0.4-3
- daemon: reset state to idle after relay flow so Status() does not return stale state
- gui: route terminal states (idle/error) to relay screen when disconnecting a relay session

* Mon May  4 2026 Anatolii Vorona <vorona.tolik@gmail.com> - 1.0.4-2
- spec: add BuildRequires systemd-rpm-macros to fix _unitdir/_presetdir expansion in %%files

* Mon May  4 2026 Anatolii Vorona <vorona.tolik@gmail.com> - 1.0.4-1
- gui: downgrade gtk4 → 0.10 and libadwaita → 0.7 for FC43 COPR compatibility

* Mon May  4 2026 Anatolii Vorona <vorona.tolik@gmail.com> - 1.0.3-1
- ci: release workflow — static Linux CLI binaries (amd64/arm64/ppc64le) attached to GitHub Release on v* tags

* Sun May  3 2026 Anatolii Vorona <vorona.tolik@gmail.com> - 1.0.2-1
- dev: add .pre-commit-config.yaml with go-unit-tests (-race) and rpmlint hooks

* Sun May  3 2026 Anatolii Vorona <vorona.tolik@gmail.com> - 1.0.1-1
- about: show app version and engine version (go-openlawsvpn CARGO_PKG_VERSION)
- about: replace BSL-1.1 legal section with LGPL-2.1-or-later with usage exception
- about: notice.txt updated — remove stale openvpn3-core/ASIO/OpenSSL entries
- gui: fix app icon in Dash/Alt+Tab — register ~/.local/share/icons in GTK search path
- gui: autostart .desktop Icon= changed to com.openlawsvpn.gui (heart+lock)
- relay: merge connected agent status onto agent row; Disconnect button on row
- fix: clone token before thread spawn to fix borrow-after-move build error

* Sun May  3 2026 Anatolii Vorona <vorona.tolik@gmail.com> - 1.0.0-2
- about: show app version and engine version (go-openlawsvpn CARGO_PKG_VERSION)
- about: replace BSL-1.1 legal section with LGPL-2.1-or-later with usage exception
- about: notice.txt updated — remove stale openvpn3-core/ASIO/OpenSSL entries
- gui: fix app icon in Dash/Alt+Tab — register ~/.local/share/icons in GTK search path
- gui: autostart .desktop Icon= changed to com.openlawsvpn.gui (heart+lock)
- relay: merge connected agent status onto agent row; Disconnect button on row
- fix: clone token before thread spawn to fix borrow-after-move build error

* Sun May  3 2026 Anatolii Vorona <vorona.tolik@gmail.com> - 1.0.0-1
- security: relay WS token moved from URL to auth frame (BC1)
- security: relay HTTP API uses Authorization: Bearer header on all routes (F4)
- security: session ownership check on /execute — prevents cross-org credential delivery (F3)
- security: relay-pending DDB table with 60s TTL for unauthenticated WS connections
- security: agent_id regex validation and hostname truncation (F6)
- security: payload size limits on /execute — 32 KB ovpn_config, 64 KB saml_response (F8)
- security: disable raw execute-api endpoint on HTTP API (F9)
- security: WS API access logging enabled with 30-day CloudWatch retention (F10)
- security: agent log output scrubbed for passwords/secrets/saml/keys (F13)
- security: CloudWatch alarm relay-ws-auth-failures-high — fires at >=20 4001s per 5 min (F14)
- security: crypto/rand for UUID, wsKey, and WS mask key generation (BC4)
- security: protocol version field in all agent<->server messages (BC3)
- gui: app icon changed to heart+lock design (openlaws=openlove)
- relay: remove custom relay URL input from GUI and Android — hardcoded to production endpoint
  Use OPENLAWSVPN_RELAY_URL env var for local testing

* Sun May  3 2026 Anatolii Vorona <vorona.tolik@gmail.com> - 0.2.9-1
- license: change from BSL-1.1 to LGPL-2.1-or-later + usage exception
- gui: add dedicated app icon (com.openlawsvpn.gui.svg) — shield+lock design in brand colors
  Fixes GNOME launcher showing broken-heart tray icon instead of app icon
- desktop: Icon= updated to com.openlawsvpn.gui
- gui: window icon-name uses app icon (com.openlawsvpn.gui) instead of tray state icon
- cli: add detailed -h/--help usage text with USAGE, MODES, OPTIONS, EXAMPLES sections
- relay: exit cleanly on server-initiated disconnect (v0.2.8)
- relay: send standby status after tunnel drops (v0.2.7)

* Sat May  2 2026 Anatolii Vorona <vorona.tolik@gmail.com> - 0.1.0-22
- relay: suppress spurious idle signal that stalled GUI at "Connecting to VPN for Phase 1"
- relay: handle fragmented WebSocket frames; skip empty keepalive frames
- gui: fix Cancel button routing — relay Connecting/WaitingSaml states now reach relay screen
- gui: remove duplicate bottom-bar Cancel button; per-agent row Cancel is the correct UX
- gui: fix relay default URL (api.relay.openlawsvpn.com, was missing api. subdomain)
- cli: add -daemon/-pidfile/-logfile flags for background-after-connect mode
- ci: vpn-integration workflow uses -daemon flag instead of log polling

* Sat May  2 2026 Anatolii Vorona <vorona.tolik@gmail.com> - 0.1.0-21
- spec: add openlawsvpn-cli subpackage shipping /usr/bin/openlawsvpn-cli
- rename repo and Go module from go-openvpn3 to go-openlawsvpn

* Sat May  2 2026 Anatolii Vorona <vorona.tolik@gmail.com> - 0.1.0-20
- relay: CI mode emits OVPN3_TUNNEL_UP to both stdout and stderr
- ci: GHA workflow captures stdout+stderr (&>/tmp/ovpn3.log) so OVPN3_TUNNEL_UP is always detected
- relay-endpoint default updated to wss://ws.relay.openlawsvpn.com/ws
- docs: ci-relay.md usage guide

* Fri May  1 2026 Anatolii Vorona <vorona.tolik@gmail.com> - 0.1.0-19
- gui: ship openlawsvpn-disconnected/connected SVG icons in hicolor theme
  Fixes generic blue-gear icon in dock and wrong padlock in GNOME launcher
- gui: set window icon-name to openlawsvpn-disconnected at startup
- desktop: Icon= now uses openlawsvpn-disconnected (matches tray icon)

* Fri May  1 2026 Anatolii Vorona <vorona.tolik@gmail.com> - 0.1.0-18
- feat(relay): Option A relay — daemon owns :35001; new ConnectRelay D-Bus method
  performs Phase 1 + ACS capture + POST /execute to relay API
- gui: new Relay tab with org token settings, live agent list (5s poll),
  per-agent Connect button, relay state display
- vpn_service: RelayDelivering/RelayConnected states; VpnCommand::ConnectRelay

* Fri May  1 2026 Anatolii Vorona <vorona.tolik@gmail.com> - 0.1.0-17
- tray: add "Launch on Login" checkmark menu item backed by XDG autostart
  (~/.config/autostart/openlawsvpn-gui.desktop)

* Thu Apr 30 2026 Anatolii Vorona <vorona.tolik@gmail.com> - 0.1.0-16
- spec: fix bogus changelog dates (Wed → Thu for Apr 30 2026)
- build: switch linker to mold for x86_64/aarch64/armv7/ppc64le/ppc64
- build: trim tokio features (full → rt+rt-multi-thread+sync+macros)
- build: codegen-units=16 + lto=thin for parallel LLVM codegen

* Thu Apr 30 2026 Anatolii Vorona <vorona.tolik@gmail.com> - 0.1.0-15
- tray: replace idle_add_local busy-loop with futures_channel mpsc + spawn_future_local
  Eliminates 100% CPU usage caused by zero-timeout ppoll spinning on every GLib tick

* Thu Apr 30 2026 Anatolii Vorona <vorona.tolik@gmail.com> - 0.1.0-14
- dns: replace resolvectl subprocess with direct D-Bus calls to
  org.freedesktop.resolve1 (SetLinkDNS, SetLinkDomains, RevertLink)
  Eliminates polkit interactive-auth failure for the openlawsvpn system user
- tray: emit LayoutUpdated on state change so the menu label updates
  correctly between "Connect VPN" and "Disconnect VPN"

* Thu Apr 30 2026 Anatolii Vorona <vorona.tolik@gmail.com> - 0.1.0-13
- spec: ship 90-openlawsvpn.preset so openlawsvpn-daemon.service is enabled
  automatically on fresh install (systemctl preset run by %%systemd_post)

* Thu Apr 30 2026 Anatolii Vorona <vorona.tolik@gmail.com> - 0.1.0-12
- daemon: move to system bus — system service under dedicated openlawsvpn user
  Eliminates the Fedora 44 user-session user-namespace problem entirely.
  System services run in the host init user namespace; file capabilities and
  CAP_NET_ADMIN work without any workarounds.
  D-Bus policy (system.d/) allows openlawsvpn group to call the daemon.
  RPM %%pre creates openlawsvpn user/group and adds human users to the group.
  GUI connects to system bus instead of session bus.

* Thu Apr 30 2026 Anatolii Vorona <vorona.tolik@gmail.com> - 0.1.0-11
- daemon: switch to system service template (superseded by 0.1.0-12)

* Thu Apr 30 2026 Anatolii Vorona <vorona.tolik@gmail.com> - 0.1.0-10
- daemon: attempted AmbientCapabilities-only approach (superseded by 0.1.0-12)

* Wed Apr 29 2026 Anatolii Vorona <vorona.tolik@gmail.com> - 0.1.0-9
- daemon: add PrivateUsers=no to service unit (superseded by 0.1.0-12)

* Tue Apr 28 2026 Anatolii Vorona <vorona.tolik@gmail.com> - 0.1.0-8
- spec: rewrite per Fedora Rust Packaging Guidelines
- add %%bcond check 0 (mandatory for Rust packages)
- add %%cargo_license_summary / %%cargo_license > LICENSE.dependencies in %%build
- add License conjunction for gui subpackage
- replace %%cargo_install with explicit install from target/rpm/
- add SourceLicense tag

* Tue Apr 28 2026 Anatolii Vorona <vorona.tolik@gmail.com> - 0.1.0-7
- spec: drop vendor tarball; use %%cargo_generate_buildrequires

* Tue Apr 28 2026 Anatolii Vorona <vorona.tolik@gmail.com> - 0.1.0-4
- daemon: add user@.service.d drop-in for CAP_NET_ADMIN

* Tue Apr 28 2026 Anatolii Vorona <vorona.tolik@gmail.com> - 0.1.0-3
- spec: extract inline D-Bus service and .desktop files to packaging/

* Tue Apr 28 2026 Anatolii Vorona <vorona.tolik@gmail.com> - 0.1.0-2
- Initial package: Go daemon + GTK4 GUI replacing openvpn3-linux dependency
