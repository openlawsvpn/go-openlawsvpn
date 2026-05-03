// SPDX-License-Identifier: LGPL-2.1-or-later
mod about_view;
mod connection;
mod log_view;
mod profile_store;
mod relay;
mod relay_store;
mod tray;
mod vpn_service;

use about_view::AboutView;
use connection::{ConnectionScreen, ConnectionState};
use log_view::LogView;
use profile_store::ProfileStore;
use relay::RelayScreen;
use tray::TrayState;
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
        // Install SVG icons before the first window appears so the launcher,
        // taskbar, and Alt+Tab switcher all show the openlawsvpn icon.
        tray::install_icons();
    });

    app.connect_activate(|app| {
        let provider = CssProvider::new();
        provider.load_from_data(STYLE);
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
    let relay_screen = RelayScreen::new(store.clone(), vpn.clone());
    let log_view = Rc::new(LogView::new());
    let about_view = AboutView::new();

    let stack = ViewStack::new();

    let conn_page = stack.add_titled(
        connection_screen.borrow().get_widget(),
        Some("connect"),
        "Connect",
    );
    conn_page.set_icon_name(Some("network-vpn-symbolic"));

    let relay_page = stack.add_titled(
        relay_screen.borrow().get_widget(),
        Some("relay"),
        "Relay",
    );
    relay_page.set_icon_name(Some("network-server-symbolic"));

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
    window.set_icon_name(Some(tray::ICON_APP_NAME));

    // ── System tray ─────────────────────────────────────────────────────────
    let tray_state = Arc::new(Mutex::new(TrayState::default()));

    let tray_guard: Option<tray::TrayGuard> = tray::register(
        window.clone(),
        tray_state.clone(),
        vpn.cmd_tx.clone(),
        &vpn.rt_handle,
    );

    // X button / Alt+F4: always exit the app.
    window.connect_close_request(move |_w| {
        std::process::exit(0);
    });

    // _ (minimize) button: hide to tray instead of minimizing when tray is active.
    // On Wayland the compositor never reports ToplevelState::MINIMIZED back to the
    // client, so listening for state_notify doesn't work. Instead we replace the
    // default CSD window controls with our own buttons that call set_visible(false).
    if tray_guard.is_some() {
        header.set_show_end_title_buttons(false);

        let close_btn = gtk4::Button::from_icon_name("window-close-symbolic");
        close_btn.add_css_class("flat");
        close_btn.connect_clicked(|_| std::process::exit(0));

        let minimize_btn = gtk4::Button::from_icon_name("window-minimize-symbolic");
        minimize_btn.add_css_class("flat");
        let win_weak = window.downgrade();
        minimize_btn.connect_clicked(move |_| {
            if let Some(w) = win_weak.upgrade() {
                w.set_visible(false);
            }
        });

        // pack_end items are ordered right-to-left: close first = far right,
        // minimize second = just left of close → standard [_ ×] layout.
        header.pack_end(&close_btn);
        header.pack_end(&minimize_btn);
    }

    // ── VPN event loop ───────────────────────────────────────────────────────
    let mut event_rx = vpn.take_event_rx();

    // Track whether the current session was initiated from the relay screen,
    // so Connecting/WaitingSaml states are routed there (not to connection screen).
    let in_relay_flow = Rc::new(RefCell::new(false));

    glib::spawn_future_local(async move {
        while let Some(event) = event_rx.next().await {
            match event {
                VpnEvent::StateChanged { ref state, ref profile_path } => {
                    // Relay-specific states always belong to the relay screen.
                    // Connecting/WaitingSaml are also relay-owned when a relay
                    // session is active.
                    let is_relay_specific = matches!(state,
                        VpnState::RelayDelivering { .. } | VpnState::RelayConnected { .. }
                    );
                    if is_relay_specific {
                        *in_relay_flow.borrow_mut() = true;
                    } else if matches!(state, VpnState::Idle | VpnState::Error(_)) {
                        *in_relay_flow.borrow_mut() = false;
                    }
                    let is_relay = is_relay_specific || *in_relay_flow.borrow();
                    // Open browser for SAML — applies to both local and relay flows.
                    if let VpnState::WaitingSaml { ref saml_url } = state {
                        if !saml_url.is_empty() {
                            log_view.append_line("saml: opening browser for authentication…");
                            if let Err(e) = std::process::Command::new("gio")
                                .args(["open", saml_url])
                                .stdout(std::process::Stdio::null())
                                .stderr(std::process::Stdio::null())
                                .spawn()
                            {
                                eprintln!("saml: gio open failed: {e}");
                                log_view.append_line(&format!("saml: could not open browser: {e}"));
                            }
                        }
                    }
                    if is_relay {
                        relay_screen.borrow().set_relay_state(state);
                    } else {
                        let connected = matches!(state, VpnState::Connected { .. });
                        if let Ok(mut ts) = tray_state.lock() {
                            ts.connected = connected;
                            if !profile_path.is_empty() {
                                ts.last_profile_path = profile_path.clone();
                            }
                        }
                        if let Some(ref guard) = tray_guard {
                            guard.notify_state(connected);
                        }
                        let ui_state = vpn_state_to_ui(state);
                        connection_screen.borrow_mut().set_state(ui_state, profile_path.clone());
                    }
                }
                VpnEvent::RelayFlowStarted => {
                    *in_relay_flow.borrow_mut() = true;
                    relay_screen.borrow().set_relay_state(&VpnState::Connecting);
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
        VpnState::RelayDelivering { .. } | VpnState::RelayConnected { .. } => ConnectionState::Idle,
    }
}
