// SPDX-License-Identifier: LGPL-2.1-or-later
//
// System tray via the StatusNotifierItem D-Bus protocol.
// Works with GNOME + appindicatorsupport extension, KDE Plasma, and any
// desktop implementing the freedesktop StatusNotifierItem spec.

use gtk4::glib;
use gtk4::prelude::*;
use libadwaita::ApplicationWindow;
use zbus::{interface, Connection};
use zbus::object_server::SignalEmitter;

use std::sync::{Arc, Mutex, mpsc as stdmpsc};

const ICON_CONNECTED_NAME: &str = "openlawsvpn-connected";
const ICON_DISCONNECTED_NAME: &str = "openlawsvpn-disconnected";

const ICON_CONNECTED_SVG: &[u8] = include_bytes!("../resources/icons/vpn-connected.svg");
const ICON_DISCONNECTED_SVG: &[u8] = include_bytes!("../resources/icons/vpn-disconnected.svg");

/// Shared VPN state mirrored into the tray icon.
#[derive(Clone, Default)]
pub struct TrayState {
    pub connected: bool,
    /// Config path of the last successfully started connection; used by tray "Connect VPN".
    pub last_profile_path: String,
}

/// Commands the D-Bus task sends back to the GTK main thread.
pub enum TrayCmd {
    ShowWindow,
    Quit,
    VpnConnect,
    VpnDisconnect,
}

struct StatusNotifierItem {
    state: Arc<Mutex<TrayState>>,
    cmd_tx: stdmpsc::SyncSender<TrayCmd>,
    icon_theme_path: String,
}

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
        // Always "Active" so the tray icon is always shown (not dimmed/hidden).
        // The connected state is conveyed via the icon name change instead.
        "Active"
    }

    #[zbus(property)]
    fn icon_name(&self) -> String {
        if self.state.lock().map(|s| s.connected).unwrap_or(false) {
            ICON_CONNECTED_NAME.into()
        } else {
            ICON_DISCONNECTED_NAME.into()
        }
    }

    #[zbus(property)]
    fn icon_theme_path(&self) -> &str {
        &self.icon_theme_path
    }

    #[zbus(property)]
    fn attention_icon_name(&self) -> &str {
        ICON_CONNECTED_NAME
    }

    #[zbus(property)]
    fn title(&self) -> &str {
        "openlawsvpn"
    }

    #[zbus(property)]
    fn tooltip(&self) -> (String, Vec<(i32, i32, Vec<u8>)>, String, String) {
        let status = if self.state.lock().map(|s| s.connected).unwrap_or(false) {
            "Connected"
        } else {
            "Disconnected"
        };
        (
            self.icon_name(),
            vec![],
            "openlawsvpn".into(),
            status.into(),
        )
    }

    #[zbus(property)]
    fn menu(&self) -> zbus::zvariant::OwnedObjectPath {
        zbus::zvariant::OwnedObjectPath::try_from("/StatusNotifierItem/Menu")
            .unwrap_or_else(|_| zbus::zvariant::OwnedObjectPath::try_from("/").unwrap())
    }

    // Left-click: show/raise the window.
    fn activate(&self, _x: i32, _y: i32) {
        let _ = self.cmd_tx.send(TrayCmd::ShowWindow);
    }

    fn context_menu(&self, _x: i32, _y: i32) {}
    fn scroll(&self, _delta: i32, _orientation: &str) {}

    #[zbus(signal)]
    async fn new_status(signal_ctxt: &SignalEmitter<'_>, status: &str) -> zbus::Result<()>;
    #[zbus(signal)]
    async fn new_icon(signal_ctxt: &SignalEmitter<'_>) -> zbus::Result<()>;
    #[zbus(signal)]
    async fn new_tooltip(signal_ctxt: &SignalEmitter<'_>) -> zbus::Result<()>;
}

// ── DBusMenu ─────────────────────────────────────────────────────────────────

struct DbusMenu {
    cmd_tx: stdmpsc::SyncSender<TrayCmd>,
    state: Arc<Mutex<TrayState>>,
    revision: u32,
}

unsafe impl Send for DbusMenu {}
unsafe impl Sync for DbusMenu {}

#[interface(name = "com.canonical.dbusmenu")]
impl DbusMenu {
    #[zbus(property)]
    fn version(&self) -> u32 { 3 }

    #[zbus(property)]
    fn text_direction(&self) -> &str { "ltr" }

    #[zbus(property)]
    fn status(&self) -> &str { "normal" }

    #[zbus(property)]
    fn icon_theme_path(&self) -> Vec<String> { vec![] }

    fn get_layout(
        &self,
        _parent_id: i32,
        _recursion_depth: i32,
        _property_names: Vec<String>,
    ) -> (u32, (i32, std::collections::HashMap<String, zbus::zvariant::Value<'_>>, Vec<zbus::zvariant::Value<'_>>)) {
        use std::collections::HashMap;
        use zbus::zvariant::Value;

        let connected = self.state.lock().map(|s| s.connected).unwrap_or(false);
        let vpn_label = if connected { "Disconnect VPN" } else { "Connect VPN" };

        let show_item: (i32, HashMap<String, Value>, Vec<Value>) = (
            1,
            [
                ("label".to_string(), Value::from("Show window")),
                ("enabled".to_string(), Value::from(true)),
                ("visible".to_string(), Value::from(true)),
            ].into(),
            vec![],
        );
        let vpn_item: (i32, HashMap<String, Value>, Vec<Value>) = (
            2,
            [
                ("label".to_string(), Value::from(vpn_label)),
                ("enabled".to_string(), Value::from(true)),
                ("visible".to_string(), Value::from(true)),
            ].into(),
            vec![],
        );
        let sep: (i32, HashMap<String, Value>, Vec<Value>) = (
            3,
            [("type".to_string(), Value::from("separator"))].into(),
            vec![],
        );
        let quit_item: (i32, HashMap<String, Value>, Vec<Value>) = (
            4,
            [
                ("label".to_string(), Value::from("Quit")),
                ("enabled".to_string(), Value::from(true)),
                ("visible".to_string(), Value::from(true)),
            ].into(),
            vec![],
        );

        let root: (i32, HashMap<String, Value>, Vec<Value>) = (
            0,
            HashMap::new(),
            vec![
                Value::from(show_item),
                Value::from(vpn_item),
                Value::from(sep),
                Value::from(quit_item),
            ],
        );

        (self.revision, root)
    }

    fn get_group_properties(
        &self,
        ids: Vec<i32>,
        _property_names: Vec<String>,
    ) -> Vec<(i32, std::collections::HashMap<String, zbus::zvariant::Value<'_>>)> {
        use std::collections::HashMap;
        use zbus::zvariant::Value;

        let connected = self.state.lock().map(|s| s.connected).unwrap_or(false);
        let vpn_label = if connected { "Disconnect VPN" } else { "Connect VPN" };

        ids.into_iter().filter_map(|id| {
            let props: HashMap<String, Value> = match id {
                1 => [
                    ("label".to_string(), Value::from("Show window")),
                    ("enabled".to_string(), Value::from(true)),
                    ("visible".to_string(), Value::from(true)),
                ].into(),
                2 => [
                    ("label".to_string(), Value::from(vpn_label)),
                    ("enabled".to_string(), Value::from(true)),
                    ("visible".to_string(), Value::from(true)),
                ].into(),
                3 => [("type".to_string(), Value::from("separator"))].into(),
                4 => [
                    ("label".to_string(), Value::from("Quit")),
                    ("enabled".to_string(), Value::from(true)),
                    ("visible".to_string(), Value::from(true)),
                ].into(),
                _ => return None,
            };
            Some((id, props))
        }).collect()
    }

    fn event(&self, id: i32, event_id: &str, _data: zbus::zvariant::Value<'_>, _timestamp: u32) {
        if event_id == "clicked" {
            match id {
                1 => { let _ = self.cmd_tx.send(TrayCmd::ShowWindow); }
                2 => {
                    let connected = self.state.lock().map(|s| s.connected).unwrap_or(false);
                    let cmd = if connected { TrayCmd::VpnDisconnect } else { TrayCmd::VpnConnect };
                    let _ = self.cmd_tx.send(cmd);
                }
                4 => { let _ = self.cmd_tx.send(TrayCmd::Quit); }
                _ => {}
            }
        }
    }

    fn event_group(
        &self,
        events: Vec<(i32, String, zbus::zvariant::Value<'_>, u32)>,
    ) -> Vec<i32> {
        for (id, event_id, data, ts) in events {
            self.event(id, &event_id, data, ts);
        }
        vec![]
    }

    #[zbus(name = "AboutToShow")]
    fn about_to_show(&self, _id: i32) -> bool { false }
    #[zbus(name = "AboutToShowGroup")]
    fn about_to_show_group(&self, _ids: Vec<i32>) -> (Vec<i32>, Vec<i32>) { (vec![], vec![]) }

    #[zbus(signal)]
    async fn layout_updated(signal_ctxt: &SignalEmitter<'_>, revision: u32, parent: i32) -> zbus::Result<()>;
    #[zbus(signal)]
    async fn items_properties_updated(
        signal_ctxt: &SignalEmitter<'_>,
        updated: Vec<(i32, std::collections::HashMap<String, zbus::zvariant::Value<'_>>)>,
        removed: Vec<(i32, Vec<String>)>,
    ) -> zbus::Result<()>;
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Keeps the zbus connection alive. Drop to unregister.
pub struct TrayGuard {
    conn: Connection,
    state: Arc<Mutex<TrayState>>,
}

impl TrayGuard {
    /// Notify the tray that connected state changed — updates icon and tooltip.
    pub fn notify_state(&self, connected: bool) {
        if let Ok(mut s) = self.state.lock() {
            s.connected = connected;
        }
        let conn = self.conn.clone();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio rt");
            rt.block_on(async move {
                let iface_ref = conn
                    .object_server()
                    .interface::<_, StatusNotifierItem>("/StatusNotifierItem")
                    .await;
                if let Ok(iface_ref) = iface_ref {
                    let signal_ctxt = iface_ref.signal_emitter().clone();
                    let status = if connected { "Active" } else { "Active" };
                    let _ = StatusNotifierItem::new_status(&signal_ctxt, status).await;
                    let _ = StatusNotifierItem::new_icon(&signal_ctxt).await;
                    let _ = StatusNotifierItem::new_tooltip(&signal_ctxt).await;
                }
            });
        });
    }
}

/// Install custom SVG icons into the user's local icon theme (~/.local/share/icons/hicolor/scalable/apps/).
/// Returns empty string — the icons are in the standard XDG search path so no extra IconThemePath is needed.
fn install_icons() -> String {
    let base = dirs_or_home().join(".local/share/icons/hicolor/scalable/apps");
    let _ = std::fs::create_dir_all(&base);
    let _ = std::fs::write(base.join(format!("{}.svg", ICON_CONNECTED_NAME)), ICON_CONNECTED_SVG);
    let _ = std::fs::write(base.join(format!("{}.svg", ICON_DISCONNECTED_NAME)), ICON_DISCONNECTED_SVG);
    String::new()
}

fn dirs_or_home() -> std::path::PathBuf {
    std::env::var("HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("/tmp"))
}

/// Register the StatusNotifierItem on the session bus.
///
/// Returns `Some(TrayGuard)` if registration succeeded, `None` if no
/// StatusNotifierWatcher is present (tray support unavailable).
pub fn register(
    window: ApplicationWindow,
    state: Arc<Mutex<TrayState>>,
    vpn_cmd_tx: tokio::sync::mpsc::Sender<crate::vpn_service::VpnCommand>,
    rt: &tokio::runtime::Handle,
) -> Option<TrayGuard> {
    let icon_theme_path = install_icons();

    let (cmd_tx, cmd_rx) = stdmpsc::sync_channel::<TrayCmd>(8);
    let cmd_rx = Arc::new(Mutex::new(cmd_rx));

    let conn_slot: Arc<Mutex<Option<Connection>>> = Arc::new(Mutex::new(None));

    // Poll the channel from the GTK main thread using idle_add.
    {
        let window_ref = window.clone();
        let conn_slot = conn_slot.clone();
        let vpn_tx = vpn_cmd_tx.clone();
        let state = state.clone();
        glib::idle_add_local(move || {
            while let Ok(cmd) = cmd_rx.lock().unwrap().try_recv() {
                match cmd {
                    TrayCmd::ShowWindow => { window_ref.present(); }
                    TrayCmd::VpnConnect => {
                        let path = state.lock().map(|s| s.last_profile_path.clone()).unwrap_or_default();
                        if path.is_empty() {
                            // No prior connection — show window so the user can pick a profile.
                            window_ref.present();
                        } else {
                            let tx = vpn_tx.clone();
                            glib::spawn_future_local(async move {
                                tx.send(crate::vpn_service::VpnCommand::Connect { config_path: path }).await.ok();
                            });
                        }
                    }
                    TrayCmd::VpnDisconnect => {
                        let tx = vpn_tx.clone();
                        glib::spawn_future_local(async move {
                            tx.send(crate::vpn_service::VpnCommand::Disconnect).await.ok();
                        });
                    }
                    TrayCmd::Quit => {
                        if let Some(conn) = conn_slot.lock().unwrap().take() {
                            let rt = tokio::runtime::Builder::new_current_thread()
                                .enable_all()
                                .build()
                                .expect("tokio rt");
                            rt.block_on(async move { conn.close().await.ok(); });
                        }
                        std::process::exit(0);
                    }
                }
            }
            glib::ControlFlow::Continue
        });
    }

    let item = StatusNotifierItem { state: state.clone(), cmd_tx: cmd_tx.clone(), icon_theme_path };
    let menu = DbusMenu { cmd_tx, state: state.clone(), revision: 1 };

    let conn = rt.block_on(async move {
        let well_known = "org.kde.StatusNotifierItem-openlawsvpn-gui";

        let conn = zbus::connection::Builder::session()
            .ok()?
            .name(well_known)
            .ok()?
            .serve_at("/StatusNotifierItem", item)
            .ok()?
            .serve_at("/StatusNotifierItem/Menu", menu)
            .ok()?
            .build()
            .await
            .ok()?;

        let result = conn
            .call_method(
                Some("org.kde.StatusNotifierWatcher"),
                "/StatusNotifierWatcher",
                Some("org.kde.StatusNotifierWatcher"),
                "RegisterStatusNotifierItem",
                &well_known,
            )
            .await;

        if result.is_err() {
            return None;
        }

        Some(conn)
    })?;

    *conn_slot.lock().unwrap() = Some(conn.clone());

    Some(TrayGuard { conn, state })
}
