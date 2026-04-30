# SPDX-License-Identifier: LGPL-2.1-or-later
Name:           openlawsvpn
Version:        0.1.0
Release:        13%{?dist}
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
Summary:        openlawsvpn VPN daemon (D-Bus system service)
License:        BSL-1.1
Requires:       dbus
Requires:       polkit
%{?systemd_requires}

%description daemon
Background daemon that manages the VPN tunnel via go-openvpn3.
Runs as a systemd system service under the openlawsvpn user with CAP_NET_ADMIN.
Exposes com.openlawsvpn.Daemon on the system bus.

%package gui
Summary:        openlawsvpn GTK4 GUI
# GUI binary statically links Rust crates — full license conjunction required.
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

%files daemon
%license LICENSE
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

# ── Scriptlets ────────────────────────────────────────────────────────────────

%post daemon
%systemd_post openlawsvpn-daemon.service

%preun daemon
%systemd_preun openlawsvpn-daemon.service

%postun daemon
%systemd_postun_with_restart openlawsvpn-daemon.service

# ── Changelog ─────────────────────────────────────────────────────────────────

%changelog
* Wed Apr 30 2026 Anatolii Vorona <vorona.tolik@gmail.com> - 0.1.0-13
- spec: ship 90-openlawsvpn.preset so openlawsvpn-daemon.service is enabled
  automatically on fresh install (systemctl preset run by %%systemd_post)

* Wed Apr 30 2026 Anatolii Vorona <vorona.tolik@gmail.com> - 0.1.0-12
- daemon: move to system bus — system service under dedicated openlawsvpn user
  Eliminates the Fedora 44 user-session user-namespace problem entirely.
  System services run in the host init user namespace; file capabilities and
  CAP_NET_ADMIN work without any workarounds.
  D-Bus policy (system.d/) allows openlawsvpn group to call the daemon.
  RPM %%pre creates openlawsvpn user/group and adds human users to the group.
  GUI connects to system bus instead of session bus.

* Wed Apr 30 2026 Anatolii Vorona <vorona.tolik@gmail.com> - 0.1.0-11
- daemon: switch to system service template (superseded by 0.1.0-12)

* Wed Apr 30 2026 Anatolii Vorona <vorona.tolik@gmail.com> - 0.1.0-10
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
