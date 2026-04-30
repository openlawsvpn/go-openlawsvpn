# SPDX-License-Identifier: LGPL-2.1-or-later
Name:           openlawsvpn
Version:        0.1.0
Release:        11%{?dist}
Summary:        AWS Client VPN client with SAML/SSO support — pure Go stack

# Source (daemon + protocol engine): BSL-1.1
# GUI binary (statically links Rust crates): BSL-1.1 AND MIT AND Apache-2.0 AND BSD-2-Clause AND LGPL-2.1-or-later
SourceLicense:  BSL-1.1
License:        BSL-1.1

URL:            https://github.com/openlawsvpn/go-openvpn3
Source0:        {{{ git_repo_pack }}}

# Tests are not shipped in the source tree — disable check bcond.
%bcond check 0

BuildRequires:  golang >= 1.21
BuildRequires:  cargo-rpm-macros

%description
AWS Client VPN client with full SAML/SSO support.
Pure Go protocol engine (go-openvpn3) with a GTK4 GUI.
No OpenVPN Inc runtime required.

# ── Subpackages ───────────────────────────────────────────────────────────────

%package daemon
Summary:        openlawsvpn VPN daemon (D-Bus session service)
License:        BSL-1.1
Requires:       dbus
Requires:       polkit
%{?systemd_requires}

%description daemon
Background daemon that manages the VPN tunnel via go-openvpn3.
Runs as a systemd system service (User= template) with CAP_NET_ADMIN.
Exposes com.openlawsvpn.Daemon on the user's session bus.

%package gui
Summary:        openlawsvpn GTK4 GUI
# GUI binary statically links Rust crates — full license conjunction required.
# (paste output of %%cargo_license_summary after first build)
License:        BSL-1.1 AND MIT AND Apache-2.0 AND BSD-2-Clause AND LGPL-2.1-or-later
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
%setup -T -b 0 -q -n go-openvpn3
cd gui-gtk && %cargo_prep && cd -

# ── Dynamic BuildRequires ─────────────────────────────────────────────────────

%generate_buildrequires
cd gui-gtk && %cargo_generate_buildrequires && cd -

# ── Build ─────────────────────────────────────────────────────────────────────

%build
CGO_ENABLED=0 go build -o %{_builddir}/openlawsvpn-daemon ./cmd/daemon

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

# System service template: openlawsvpn-daemon@<username>.service
install -Dm644 cmd/daemon/openlawsvpn-daemon@.service \
    %{buildroot}%{_unitdir}/openlawsvpn-daemon@.service

install -Dm644 packaging/10-openlawsvpn-dns.rules \
    %{buildroot}%{_datadir}/polkit-1/rules.d/10-openlawsvpn-dns.rules

install -Dm644 packaging/com.openlawsvpn.Daemon.service \
    %{buildroot}%{_datadir}/dbus-1/services/com.openlawsvpn.Daemon.service

# Install GUI binary directly from target/rpm/ (non-crate project — do not use %%cargo_install).
install -Dm755 gui-gtk/target/rpm/openlawsvpn-gui \
    %{buildroot}%{_bindir}/openlawsvpn-gui

install -Dm644 packaging/openlawsvpn-gui.desktop \
    %{buildroot}%{_datadir}/applications/openlawsvpn-gui.desktop

# ── Check ─────────────────────────────────────────────────────────────────────

%if %{with check}
%check
cd gui-gtk && %cargo_test && cd -
%endif

# ── Files ─────────────────────────────────────────────────────────────────────

%files daemon
%license LICENSE
%caps(cap_net_admin=eip) %{_libexecdir}/openlawsvpn-daemon
%{_unitdir}/openlawsvpn-daemon@.service
%{_datadir}/dbus-1/services/com.openlawsvpn.Daemon.service
%{_datadir}/polkit-1/rules.d/10-openlawsvpn-dns.rules

%files gui
%license gui-gtk/LICENSE.dependencies
%{_bindir}/openlawsvpn-gui
%{_datadir}/applications/openlawsvpn-gui.desktop

# ── Scriptlets ────────────────────────────────────────────────────────────────

%post daemon
%systemd_post openlawsvpn-daemon@.service

%preun daemon
%systemd_preun openlawsvpn-daemon@.service

%postun daemon
%systemd_postun_with_restart openlawsvpn-daemon@.service

# ── Changelog ─────────────────────────────────────────────────────────────────

%changelog
* Wed Apr 30 2026 Anatolii Vorona <vorona.tolik@gmail.com> - 0.1.0-11
- daemon: switch from user service to system service template (openlawsvpn-daemon@.service)
  Fedora 44 user session manager runs in a delegated child user namespace; TUNSETIFF
  on the host /dev/net/tun fails for any user service even with CAP_NET_ADMIN because
  ns_capable() requires the caller to be in the network namespace's owner user namespace
  (the host init user namespace). System services with User= run in the host user
  namespace where file capabilities and CAP_NET_ADMIN work correctly.
  Enable with: sudo systemctl enable --now openlawsvpn-daemon@$USER.service

* Wed Apr 30 2026 Anatolii Vorona <vorona.tolik@gmail.com> - 0.1.0-10
- daemon: attempted AmbientCapabilities-only approach (superseded by 0.1.0-11)

* Wed Apr 29 2026 Anatolii Vorona <vorona.tolik@gmail.com> - 0.1.0-9
- daemon: add PrivateUsers=no to service unit (superseded by 0.1.0-11)

* Tue Apr 28 2026 Anatolii Vorona <vorona.tolik@gmail.com> - 0.1.0-8
- spec: rewrite per Fedora Rust Packaging Guidelines
- add %%bcond check 0 (mandatory for Rust packages)
- add %%cargo_license_summary / %%cargo_license > LICENSE.dependencies in %%build
- add License conjunction for gui subpackage (BSL-1.1 AND MIT AND Apache-2.0 AND BSD-2-Clause AND LGPL-2.1-or-later)
- replace %%cargo_install with explicit install from target/rpm/ (non-crate project rule)
- add SourceLicense tag separating source from binary license

* Tue Apr 28 2026 Anatolii Vorona <vorona.tolik@gmail.com> - 0.1.0-7
- spec: drop vendor tarball; use %%cargo_generate_buildrequires (all crates packaged in Fedora)

* Tue Apr 28 2026 Anatolii Vorona <vorona.tolik@gmail.com> - 0.1.0-4
- daemon: add user@.service.d drop-in to grant CAP_NET_ADMIN to user manager

* Tue Apr 28 2026 Anatolii Vorona <vorona.tolik@gmail.com> - 0.1.0-3
- spec: extract inline D-Bus service and .desktop files to packaging/ source files

* Tue Apr 28 2026 Anatolii Vorona <vorona.tolik@gmail.com> - 0.1.0-2
- spec: set CAP_NET_ADMIN on daemon via %%caps macro (no manual setcap needed)
- gui: system-tray support via StatusNotifierItem D-Bus protocol (appindicatorsupport on GNOME)
- gui: custom heart SVG icons — red heart (connected), yellow broken heart (disconnected)
- gui: tray icon always visible; icon swaps on state change instead of disappearing
- gui: X button exits the application; minimize (_) hides to tray
- gui: tray right-click menu — Show window, Connect/Disconnect VPN, Quit
- gui: startup state sync — shows correct Disconnect button if daemon already connected
- daemon: polkit rule for systemd-resolved DNS (no password prompt)
- daemon: verbose structured logging with microsecond timestamps
- daemon: Status() returns profile_path as 4th value for GUI sync
- daemon: emit SAMLRequired signal with explicit D-Bus name (fixes zbus name mapping)
- spec: add polkit Requires and install 10-openlawsvpn-dns.rules
- Initial package: Go daemon + GTK4 GUI replacing openvpn3-linux dependency
