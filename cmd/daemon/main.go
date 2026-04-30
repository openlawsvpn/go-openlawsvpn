// SPDX-License-Identifier: LGPL-2.1-or-later

// Command openlawsvpn-daemon is a D-Bus system service that manages VPN
// connections on behalf of the openlawsvpn GTK GUI.
//
// It exposes com.openlawsvpn.Daemon on the system bus, holds CAP_NET_ADMIN
// so that TUN creation and routing succeed without running as root, and runs
// the SAML ACS server on port 35001.
//
// Intended to run as a systemd system service:
//
//	sudo systemctl enable --now openlawsvpn-daemon
//
// The GUI calls Connect(profile_path) and subscribes to StateChanged, LogLine,
// StatsUpdate, and SAMLRequired signals. It never needs elevated privilege.
package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"
)

// introspectionXML is the D-Bus introspection XML for com.openlawsvpn.Daemon.
// Kept inline so the daemon is self-describing without extra files.
const introspectionXML = `
<node>
  <interface name="com.openlawsvpn.Daemon">
    <method name="Connect">
      <arg direction="in"  type="s" name="profile_path"/>
    </method>
    <method name="Disconnect"/>
    <method name="Status">
      <arg direction="out" type="s" name="state"/>
      <arg direction="out" type="s" name="server_ip"/>
      <arg direction="out" type="s" name="assigned_ip"/>
      <arg direction="out" type="s" name="profile_path"/>
    </method>
    <signal name="StateChanged">
      <arg type="s" name="state"/>
      <arg type="s" name="server_ip"/>
      <arg type="s" name="assigned_ip"/>
    </signal>
    <signal name="LogLine">
      <arg type="s" name="line"/>
    </signal>
    <signal name="StatsUpdate">
      <arg type="t" name="bytes_sent"/>
      <arg type="t" name="bytes_recv"/>
      <arg type="t" name="uptime_secs"/>
    </signal>
    <signal name="SAMLRequired">
      <arg type="s" name="url"/>
    </signal>
  </interface>
  ` + introspect.IntrospectDataString + `
</node>`

func main() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)
	log.SetPrefix("daemon: ")

	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		fmt.Fprintf(os.Stderr, "daemon: connect system bus: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	reply, err := conn.RequestName(dbusServiceName, dbus.NameFlagDoNotQueue)
	if err != nil {
		fmt.Fprintf(os.Stderr, "daemon: request D-Bus name: %v\n", err)
		os.Exit(1)
	}
	if reply != dbus.RequestNameReplyPrimaryOwner {
		fmt.Fprintf(os.Stderr, "daemon: name %q already taken — another instance running?\n", dbusServiceName)
		os.Exit(1)
	}

	svc := newDaemonService(conn)

	conn.Export(svc, dbus.ObjectPath(dbusObjectPath), dbusInterface)
	conn.Export(introspect.Introspectable(introspectionXML),
		dbus.ObjectPath(dbusObjectPath),
		"org.freedesktop.DBus.Introspectable",
	)

	fmt.Fprintf(os.Stderr, "daemon: serving %s on system bus\n", dbusServiceName)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	// Graceful shutdown: disconnect any active VPN session first.
	svc.Disconnect() //nolint:errcheck
	fmt.Fprintln(os.Stderr, "daemon: shutdown")
}
