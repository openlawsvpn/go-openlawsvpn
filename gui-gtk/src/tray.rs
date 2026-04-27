// SPDX-License-Identifier: LGPL-2.1-or-later
//
// System tray via the StatusNotifierItem D-Bus protocol (freedesktop.org).
// Works on GNOME (with AppIndicator/KStatusNotifierItem extension),
// KDE Plasma, and any desktop implementing the SNI spec.
//
// When the tray is not available the window simply hides on close and
// sends a GNotification so the user knows the app is still running.

use gtk4::glib;
use gtk4::prelude::*;
use libadwaita::ApplicationWindow;
use tokio::sync::mpsc;
use zbus::ConnectionBuilder;
use zbus::interface;

use std::sync::{Arc, Mutex};

/// Shared VPN state mirrored into the tray icon.
#[derive(Clone, Default)]
pub struct TrayState {
    pub connected: bool,
}

/// Commands the D-Bus thread sends back to the GTK main thread.
enum TrayCmd {
    ToggleWindow,
}

struct StatusNotifierItem {
    state: Arc<Mutex<TrayState>>,
    cmd_tx: mpsc::UnboundedSender<TrayCmd>,
}

// The struct only holds an Arc<Mutex<...>> and a channel sender — both Send+Sync.
unsafe impl Send for StatusNotifierItem {}
unsafe impl Sync for StatusNotifierItem {}

#[interface(name = "org.kde.StatusNotifierItem")]
impl StatusNotifierItem {
    #[zbus(property)]
    fn id(&self) -> &str {
        "openlawsvpn"
    }

    #[zbus(property)]
    fn category(&self) -> &str {
        "ApplicationStatus"
    }

    #[zbus(property)]
    fn status(&self) -> &str {
        if self.state.lock().map(|s| s.connected).unwrap_or(false) {
            "Active"
        } else {
            "Passive"
        }
    }

    #[zbus(property)]
    fn icon_name(&self) -> String {
        if self.state.lock().map(|s| s.connected).unwrap_or(false) {
            "network-vpn-symbolic".into()
        } else {
            "network-vpn-disconnected-symbolic".into()
        }
    }

    #[zbus(property)]
    fn title(&self) -> &str {
        "openlawsvpn"
    }

    fn activate(&self, _x: i32, _y: i32) {
        let _ = self.cmd_tx.send(TrayCmd::ToggleWindow);
    }

    fn context_menu(&self, _x: i32, _y: i32) {}
    fn scroll(&self, _delta: i32, _orientation: &str) {}
}

/// Register the StatusNotifierItem on the session bus.
///
/// `rt` must be the Tokio runtime handle from the VPN service background
/// thread — the GTK main thread has no Tokio runtime of its own.
///
/// Returns `Some` if registration succeeded. The caller must keep the
/// returned `_Guard` alive — dropping it unregisters the tray icon.
pub fn register(
    window: ApplicationWindow,
    state: Arc<Mutex<TrayState>>,
    rt: &tokio::runtime::Handle,
) -> Option<TrayGuard> {
    let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel::<TrayCmd>();

    // Wire commands back to GTK main thread via glib::spawn_future_local.
    {
        let window = window.clone();
        glib::spawn_future_local(async move {
            while let Some(cmd) = cmd_rx.recv().await {
                match cmd {
                    TrayCmd::ToggleWindow => {
                        if window.is_visible() {
                            window.set_visible(false);
                        } else {
                            window.present();
                        }
                    }
                }
            }
        });
    }

    let item = StatusNotifierItem { state, cmd_tx };

    // Register on the session bus using the background Tokio runtime.
    let conn = rt.block_on(async move {
        let conn = ConnectionBuilder::session()
            .ok()?
            .name("org.kde.StatusNotifierItem-openlawsvpn")
            .ok()?
            .serve_at("/StatusNotifierItem", item)
            .ok()?
            .build()
            .await
            .ok()?;

        // Announce ourselves to StatusNotifierWatcher (best-effort).
        let _ = conn
            .call_method(
                Some("org.kde.StatusNotifierWatcher"),
                "/StatusNotifierWatcher",
                Some("org.kde.StatusNotifierWatcher"),
                "RegisterStatusNotifierItem",
                &"org.kde.StatusNotifierItem-openlawsvpn",
            )
            .await;

        Some(conn)
    })?;

    Some(TrayGuard(conn))
}

/// Keeps the zbus connection alive. Drop to unregister.
#[allow(dead_code)]
pub struct TrayGuard(zbus::Connection);
