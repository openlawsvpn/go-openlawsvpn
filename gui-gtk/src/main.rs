// SPDX-License-Identifier: LGPL-2.1-or-later
mod about_view;
mod connection;
mod log_view;
mod profile_store;
mod tray;
mod vpn_service;

use about_view::AboutView;
use connection::{ConnectionScreen, ConnectionState};
use log_view::LogView;
use profile_store::ProfileStore;
use tray::{TrayGuard, TrayState};
use vpn_service::{VpnEvent, VpnService, VpnState};

use futures_util::StreamExt as _;
use gtk4::glib;
use gtk4::prelude::*;
use gtk4::CssProvider;
use libadwaita::{Application, ApplicationWindow, HeaderBar, ViewStack, ViewSwitcherBar};

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::{Arc, Mutex};

const APP_ID: &str = "com.openlawsvpn.gui";

const STYLE: &str = "
/* ── Log / About text area ── */
.log-view {
    background-color: #f5f5f5;
    font-family: monospace;
    font-size: 11px;
}
@media (prefers-color-scheme: dark) {
    .log-view {
        background-color: #1e1e1e;
    }
}

/* ── Profile cards ── */
.profile-card {
    border-radius: 12px;
}

/* ── Delete action coral accent ── */
.delete-action {
    color: #F78166;
}
.delete-action:hover {
    background-color: alpha(#F78166, 0.12);
}
";

fn main() {
    env_logger::init();

    let app = Application::builder()
        .application_id(APP_ID)
        .build();

    app.connect_startup(|_| {
        libadwaita::init().expect("Failed to initialize libadwaita");
    });

    app.connect_activate(|app| {
        let provider = CssProvider::new();
        provider.load_from_string(STYLE);
        gtk4::style_context_add_provider_for_display(
            &gtk4::gdk::Display::default().expect("no display"),
            &provider,
            gtk4::STYLE_PROVIDER_PRIORITY_APPLICATION,
        );
        build_ui(app);
    });

    app.run();
}

fn build_ui(app: &Application) {
    let store = Rc::new(RefCell::new(ProfileStore::new()));
    let vpn = Rc::new(VpnService::new());

    let connection_screen = ConnectionScreen::new(store.clone(), vpn.clone());
    let log_view = Rc::new(LogView::new());
    let about_view = AboutView::new();

    let stack = ViewStack::new();

    let conn_page = stack.add_titled(
        connection_screen.borrow().get_widget(),
        Some("connect"),
        "Connect",
    );
    conn_page.set_icon_name(Some("network-vpn-symbolic"));

    let log_page = stack.add_titled(&log_view.widget, Some("log"), "Log");
    log_page.set_icon_name(Some("dialog-information-symbolic"));

    let about_page = stack.add_titled(&about_view.widget, Some("about"), "About");
    about_page.set_icon_name(Some("help-about-symbolic"));

    let header = HeaderBar::new();
    let title_label = gtk4::Label::new(Some("openlawsvpn"));
    title_label.set_css_classes(&["title"]);
    header.set_title_widget(Some(&title_label));

    let switcher_bar = ViewSwitcherBar::new();
    switcher_bar.set_stack(Some(&stack));
    switcher_bar.set_reveal(true);

    let content = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
    content.append(&header);
    content.append(&stack);
    content.append(&switcher_bar);

    let window = ApplicationWindow::builder()
        .application(app)
        .title("openlawsvpn")
        .default_width(480)
        .default_height(640)
        .content(&content)
        .build();

    // ── System tray ─────────────────────────────────────────────────────────
    let tray_state = Arc::new(Mutex::new(TrayState {
        connected: false,
    }));

    // Keep the zbus connection alive for the lifetime of the app.
    let _tray_guard: Option<TrayGuard> = tray::register(window.clone(), tray_state.clone(), &vpn.rt_handle);

    // Always intercept close-request: GTK4's default handler only hides
    // the window (never destroys it), so the app would stay alive forever.
    // - With tray: hide to tray.
    // - Without tray: destroy the window so the GApplication hold is
    //   released and the main loop exits normally.
    // Background Tokio thread keeps the process alive after the GLib loop
    // exits — always exit explicitly on window close.
    window.connect_close_request(|_| {
        std::process::exit(0);
    });

    // ── VPN event loop ───────────────────────────────────────────────────────
    // Move strong Rc refs into the closure — weak refs become None after
    // build_ui() returns because the GTK stack only holds the inner widget.
    let mut event_rx = vpn.take_event_rx();

    glib::spawn_future_local(async move {
        while let Some(event) = event_rx.next().await {
            match event {
                VpnEvent::StateChanged(state) => {
                    // Keep tray icon state in sync
                    if let Ok(mut ts) = tray_state.lock() {
                        ts.connected = matches!(state, VpnState::Connected { .. });
                    }
                    let ui_state = vpn_state_to_ui(&state);
                    connection_screen.borrow_mut().set_state(ui_state);
                }
                VpnEvent::LogLine(line) => {
                    log_view.append_line(&line);
                }
                VpnEvent::StatsUpdate { bytes_sent, bytes_recv, uptime_secs } => {
                    log_view.append_line(&format!(
                        "stats: ↑{} ↓{} up {}s",
                        bytes_sent, bytes_recv, uptime_secs
                    ));
                }
            }
        }
    });

    window.present();
}

fn vpn_state_to_ui(state: &VpnState) -> ConnectionState {
    match state {
        VpnState::Idle => ConnectionState::Idle,
        VpnState::Connecting => ConnectionState::Connecting,
        VpnState::WaitingSaml { .. } => ConnectionState::WaitingSaml,
        VpnState::Connected { server_ip, assigned_ip } => ConnectionState::Connected {
            server_ip: server_ip.clone(),
            assigned_ip: assigned_ip.clone(),
        },
        VpnState::Disconnecting => ConnectionState::Disconnecting,
        VpnState::NeedReauth => ConnectionState::NeedReauth { reason: String::new() },
        VpnState::Error(msg) => ConnectionState::Error { message: msg.clone() },
    }
}
