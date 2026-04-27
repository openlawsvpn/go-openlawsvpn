# SPDX-License-Identifier: LGPL-2.1-or-later
%global goipath github.com/openlawsvpn/go-openvpn3
Name:           openlawsvpn
Version:        0.1.0
Release:        1%{?dist}
Summary:        AWS Client VPN client with SAML/SSO support — pure Go stack

License:        BSL-1.1
URL:            https://github.com/openlawsvpn/go-openvpn3
Source0:        {{{ git_repo_pack }}}

BuildRequires:  golang >= 1.21
BuildRequires:  go-rpm-macros
BuildRequires:  cargo-rpm-macros
BuildRequires:  rust
BuildRequires:  cargo
BuildRequires:  gtk4-devel
BuildRequires:  libadwaita-devel
BuildRequires:  dbus-devel
BuildRequires:  systemd-rpm-macros

%package daemon
Summary:        openlawsvpn VPN daemon (D-Bus session service)
Requires:       dbus
%{?systemd_requires}

%description daemon
Background daemon that manages the VPN tunnel via go-openvpn3.
Runs as a systemd user service with CAP_NET_ADMIN — no root required.
Exposes com.openlawsvpn.Daemon on the session bus.

%package gui
Summary:        openlawsvpn GTK4 GUI
Requires:       openlawsvpn-daemon = %{version}-%{release}
Requires:       gtk4
Requires:       libadwaita
Requires:       dbus

%description gui
GTK4 + libadwaita desktop client for openlawsvpn.
Communicates with openlawsvpn-daemon via D-Bus.
Includes system-tray support via StatusNotifierItem.

%description
AWS Client VPN client with full SAML/SSO support.
Pure Go protocol engine (go-openvpn3) with a GTK4 GUI.
No OpenVPN Inc runtime required.

# ── Prep ──────────────────────────────────────────────────────────────────────

%prep
%setup -T -b 0 -q -n go-openvpn3
%goprep %{goipath}
cd gui-gtk && %cargo_prep && cd -

%generate_buildrequires
cd gui-gtk && %cargo_generate_buildrequires && cd -

# ── Build ──────────────────────────────────────────────────────────────────────

%build
export CGO_ENABLED=0
%gobuild -o %{_builddir}/openlawsvpn-daemon %{goipath}/cmd/daemon

cd gui-gtk && %cargo_build && cd -

# ── Install ────────────────────────────────────────────────────────────────────

%install
install -Dm755 %{_builddir}/openlawsvpn-daemon \
    %{buildroot}%{_libexecdir}/openlawsvpn-daemon

install -Dm644 cmd/daemon/openlawsvpn-daemon.service \
    %{buildroot}%{_userunitdir}/openlawsvpn-daemon.service

mkdir -p %{buildroot}%{_datadir}/dbus-1/services
cat > %{buildroot}%{_datadir}/dbus-1/services/com.openlawsvpn.Daemon.service << 'EOF'
[D-BUS Service]
Name=com.openlawsvpn.Daemon
Exec=%{_libexecdir}/openlawsvpn-daemon
SystemdService=openlawsvpn-daemon.service
EOF

cd gui-gtk && %cargo_install && cd -

mkdir -p %{buildroot}%{_datadir}/applications
cat > %{buildroot}%{_datadir}/applications/openlawsvpn-gui.desktop << 'EOF'
[Desktop Entry]
Name=openlawsvpn
Comment=AWS Client VPN
Exec=openlawsvpn-gui
Icon=network-vpn
Terminal=false
Type=Application
Categories=Network;
Keywords=vpn;aws;saml;
EOF

# ── Files ──────────────────────────────────────────────────────────────────────

%files daemon
%license LICENSE
%{_libexecdir}/openlawsvpn-daemon
%{_userunitdir}/openlawsvpn-daemon.service
%{_datadir}/dbus-1/services/com.openlawsvpn.Daemon.service

%files gui
%{_bindir}/openlawsvpn-gui
%{_datadir}/applications/openlawsvpn-gui.desktop

# ── Scriptlets ─────────────────────────────────────────────────────────────────

%post daemon
%systemd_user_post openlawsvpn-daemon.service

%preun daemon
%systemd_user_preun openlawsvpn-daemon.service

%postun daemon
%systemd_user_postun_with_restart openlawsvpn-daemon.service

# ── Changelog ──────────────────────────────────────────────────────────────────

%changelog
* Mon Apr 28 2026 openlawsvpn contributors <security@openlawsvpn.com> - 0.1.0-1
- Initial package: Go daemon + GTK4 GUI replacing openvpn3-linux dependency
