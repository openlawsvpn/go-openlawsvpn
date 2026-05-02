// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Relay screen — lets the user authenticate a remote headless agent.
//
// Flow:
//   1. User enters org token and saves.
//   2. Agent list auto-refreshes every 5 s (GET /agents?token=).
//   3. User selects a profile + clicks Connect on a standby agent.
//   4. GUI calls daemon ConnectRelay → daemon does Phase 1 + ACS + POST /execute.
//   5. GUI watches StateChanged for relay_delivering / relay_connected.

use gtk4::glib;
use gtk4::prelude::*;
use gtk4::{
    Box as GtkBox, Button, Label, ListBox, Orientation,
    ScrolledWindow, SelectionMode, Spinner,
};
use libadwaita::prelude::*;
use libadwaita::{ActionRow, EntryRow, PreferencesGroup, Toast, ToastOverlay};

use std::cell::RefCell;
use std::rc::Rc;

use crate::profile_store::ProfileStore;
use crate::relay_store::{RelaySettings, DEFAULT_RELAY_URL};
use crate::vpn_service::{VpnCommand, VpnService};

// ── Agent data ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Deserialize)]
pub struct AgentInfo {
    pub agent_id: String,
    pub hostname: String,
    pub status: String,
    pub assigned_ip: Option<String>,
}

// ── RelayScreen ───────────────────────────────────────────────────────────────

pub struct RelayScreen {
    pub widget: GtkBox,
    pub toast_overlay: ToastOverlay,
    store: Rc<RefCell<ProfileStore>>,
    vpn: Rc<VpnService>,
    settings: Rc<RefCell<RelaySettings>>,
    agents: Rc<RefCell<Vec<AgentInfo>>>,
    agent_list: ListBox,
    no_agents_label: Label,
    agents_scroll: ScrolledWindow,
    status_label: Label,
    spinner: Spinner,
    disconnect_btn: Button,
    busy: Rc<RefCell<bool>>,
}

impl RelayScreen {
    pub fn new(store: Rc<RefCell<ProfileStore>>, vpn: Rc<VpnService>) -> Rc<RefCell<Self>> {
        let settings = Rc::new(RefCell::new(RelaySettings::load()));

        let root = GtkBox::new(Orientation::Vertical, 0);

        let header = Label::new(Some("Relay"));
        header.set_css_classes(&["title-1"]);
        header.set_xalign(0.0);
        header.set_margin_start(16);
        header.set_margin_end(16);
        header.set_margin_top(24);
        header.set_margin_bottom(8);
        root.append(&header);

        let toast_overlay = ToastOverlay::new();
        let content = GtkBox::new(Orientation::Vertical, 0);
        toast_overlay.set_child(Some(&content));
        toast_overlay.set_vexpand(true);
        root.append(&toast_overlay);

        // ── Settings group ──────────────────────────────────────────────────

        let prefs_group = PreferencesGroup::new();
        prefs_group.set_margin_start(16);
        prefs_group.set_margin_end(16);
        prefs_group.set_margin_top(8);
        prefs_group.set_margin_bottom(8);
        content.append(&prefs_group);

        let token_row = EntryRow::new();
        token_row.set_title("Organisation Token");
        token_row.set_show_apply_button(false);
        token_row.set_text(&settings.borrow().org_token);
        prefs_group.add(&token_row);

        let endpoint_row = EntryRow::new();
        endpoint_row.set_title("Relay URL");
        endpoint_row.set_show_apply_button(false);
        // Always show the current URL (default or custom) so the user can see and edit it.
        endpoint_row.set_text(&settings.borrow().relay_url);
        prefs_group.add(&endpoint_row);

        let save_btn = Button::with_label("Save & Refresh");
        save_btn.set_css_classes(&["pill", "suggested-action"]);
        save_btn.set_margin_start(16);
        save_btn.set_margin_end(16);
        save_btn.set_margin_bottom(8);
        content.append(&save_btn);

        // ── Agent list ──────────────────────────────────────────────────────

        let agents_header = Label::new(Some("Available Agents"));
        agents_header.set_css_classes(&["heading"]);
        agents_header.set_xalign(0.0);
        agents_header.set_margin_start(16);
        agents_header.set_margin_end(16);
        agents_header.set_margin_top(8);
        agents_header.set_margin_bottom(4);
        content.append(&agents_header);

        let no_agents_label = Label::new(Some("No agents online.\nStart an agent with: openlawsvpn-cli --relay=<token>"));
        no_agents_label.set_css_classes(&["dim-label"]);
        no_agents_label.set_justify(gtk4::Justification::Center);
        no_agents_label.set_vexpand(true);
        no_agents_label.set_valign(gtk4::Align::Center);
        content.append(&no_agents_label);

        let agents_scroll = ScrolledWindow::new();
        agents_scroll.set_vexpand(true);
        agents_scroll.set_visible(false);
        agents_scroll.set_policy(gtk4::PolicyType::Never, gtk4::PolicyType::Automatic);

        let agent_list = ListBox::new();
        agent_list.set_selection_mode(SelectionMode::None);
        agent_list.set_css_classes(&["boxed-list"]);
        agent_list.set_margin_start(16);
        agent_list.set_margin_end(16);
        agent_list.set_margin_top(4);
        agent_list.set_margin_bottom(8);
        agents_scroll.set_child(Some(&agent_list));
        content.append(&agents_scroll);

        // ── Status bar ──────────────────────────────────────────────────────

        let status_row = GtkBox::new(Orientation::Horizontal, 8);
        status_row.set_margin_start(16);
        status_row.set_margin_end(16);
        status_row.set_margin_bottom(12);

        let spinner = Spinner::new();
        spinner.set_visible(false);
        status_row.append(&spinner);

        let status_label = Label::new(None);
        status_label.set_hexpand(true);
        status_label.set_xalign(0.0);
        status_label.set_wrap(true);
        status_row.append(&status_label);

        let disconnect_btn = Button::with_label("Disconnect");
        disconnect_btn.set_css_classes(&["pill", "destructive-action"]);
        disconnect_btn.set_visible(false);
        status_row.append(&disconnect_btn);

        content.append(&status_row);

        let screen = Rc::new(RefCell::new(Self {
            widget: root,
            toast_overlay,
            store,
            vpn,
            settings,
            agents: Rc::new(RefCell::new(vec![])),
            agent_list,
            no_agents_label,
            agents_scroll,
            status_label,
            spinner,
            disconnect_btn: disconnect_btn.clone(),
            busy: Rc::new(RefCell::new(false)),
        }));

        // Save & Refresh button
        {
            let sc = screen.clone();
            let token_row = token_row.clone();
            let endpoint_row = endpoint_row.clone();
            save_btn.connect_clicked(move |_| {
                let token = token_row.text().to_string();
                let url_text = endpoint_row.text().to_string().trim().to_string();
                let relay_url = if url_text.is_empty() {
                    DEFAULT_RELAY_URL.to_string()
                } else {
                    url_text
                };
                // Update the URL field to show what was actually saved.
                endpoint_row.set_text(&relay_url);
                let new_settings = RelaySettings { org_token: token, relay_url };
                sc.borrow().settings.replace(new_settings.clone());
                new_settings.save();
                sc.borrow().refresh_agents();
            });
        }

        // Disconnect button
        {
            let sc = screen.clone();
            disconnect_btn.connect_clicked(move |_| {
                let vpn = sc.borrow().vpn.clone();
                glib::spawn_future_local(async move {
                    vpn.cmd_tx.send(VpnCommand::Disconnect).await.ok();
                });
            });
        }

        // Auto-refresh agents every 5s using glib::timeout_add_seconds_local
        {
            let sc = screen.clone();
            glib::timeout_add_seconds_local(5, move || {
                let s = sc.borrow();
                if !s.settings.borrow().org_token.is_empty() && !*s.busy.borrow() {
                    drop(s);
                    sc.borrow().refresh_agents();
                }
                glib::ControlFlow::Continue
            });
        }

        // Initial load if token already saved
        if !screen.borrow().settings.borrow().org_token.is_empty() {
            screen.borrow().refresh_agents();
        }

        screen
    }

    pub fn get_widget(&self) -> &GtkBox {
        &self.widget
    }

    /// Called from main.rs on VpnEvent::StateChanged with relay states.
    pub fn set_relay_state(&self, state: &crate::vpn_service::VpnState) {
        use crate::vpn_service::VpnState;
        match state {
            VpnState::Connecting => {
                self.set_busy(true, "Connecting to VPN for Phase 1…");
            }
            VpnState::WaitingSaml { .. } => {
                self.set_busy(true, "Waiting for SAML login…");
            }
            VpnState::RelayDelivering { .. } => {
                self.set_busy(true, "Delivering credentials to agent…");
            }
            VpnState::RelayConnected { agent_id } => {
                self.set_busy(false, &format!("Agent {} tunnel is up.", agent_id));
                self.disconnect_btn.set_visible(true);
                self.refresh_agents();
            }
            VpnState::Error(msg) => {
                self.set_busy(false, &format!("Error: {}", msg));
                self.disconnect_btn.set_visible(false);
                let toast = Toast::new(&format!("Relay error: {}", msg));
                self.toast_overlay.add_toast(toast);
                self.refresh_agents();
            }
            VpnState::Idle => {
                self.set_busy(false, "");
                self.disconnect_btn.set_visible(false);
                self.refresh_agents();
            }
            _ => {}
        }
    }

    fn set_busy(&self, busy: bool, msg: &str) {
        *self.busy.borrow_mut() = busy;
        self.spinner.set_visible(busy);
        if busy { self.spinner.start(); } else { self.spinner.stop(); }
        self.status_label.set_text(msg);
        self.status_label.set_visible(!msg.is_empty());
        self.rebuild_agent_rows();
    }

    fn refresh_agents(&self) {
        let token = self.settings.borrow().org_token.clone();
        let relay_url = self.settings.borrow().relay_url.clone();
        if token.is_empty() {
            return;
        }

        let agents_out = self.agents.clone();
        let list = self.agent_list.clone();
        let no_label = self.no_agents_label.clone();
        let scroll = self.agents_scroll.clone();
        let busy = self.busy.clone();
        let store = self.store.clone();
        let vpn = self.vpn.clone();
        let toast = self.toast_overlay.clone();
        let disconnect_btn = self.disconnect_btn.clone();
        let status_label = self.status_label.clone();

        // Spawn a plain OS thread for the blocking HTTP call and send the result
        // back via a oneshot channel. glib::spawn_future_local can then await it
        // without needing a Tokio runtime on the GTK main thread.
        let (tx, rx) = futures_channel::oneshot::channel::<Result<Vec<AgentInfo>, String>>();
        let url = format!("{}/agents?token={}", relay_url, urlencoding::encode(&token));
        std::thread::spawn(move || {
            let result = reqwest::blocking::get(&url)
                .and_then(|r| r.error_for_status())
                .and_then(|r| r.json::<Vec<AgentInfo>>())
                .map_err(|e| e.to_string());
            let _ = tx.send(result);
        });

        glib::spawn_future_local(async move {
            let agents = match rx.await {
                Ok(Ok(a)) => a,
                Ok(Err(e)) => {
                    // Show network errors in the status label instead of panicking.
                    no_label.set_visible(true);
                    no_label.set_text(&format!("Could not reach relay: {e}"));
                    scroll.set_visible(false);
                    return;
                }
                Err(_) => return, // sender dropped (thread panicked)
            };

            *agents_out.borrow_mut() = agents.clone();

            // Rebuild agent rows on GTK thread
            while let Some(child) = list.first_child() {
                list.remove(&child);
            }

            if agents.is_empty() {
                no_label.set_text("No agents online.\nStart an agent with: openlawsvpn-cli --relay=<token>");
                no_label.set_visible(true);
                scroll.set_visible(false);
                return;
            }
            no_label.set_visible(false);
            scroll.set_visible(true);

            let any_busy = *busy.borrow();
            let profiles = store.borrow().list();

            for agent in &agents {
                let row = ActionRow::new();
                let ip_str = agent.assigned_ip.as_deref().unwrap_or("");
                row.set_title(&agent.hostname);
                let subtitle = if ip_str.is_empty() {
                    agent.status.clone()
                } else {
                    format!("{} — {}", agent.status, ip_str)
                };
                row.set_subtitle(&subtitle);

                if agent.status == "standby" && !any_busy {
                    let connect_btn = Button::with_label("Connect");
                    connect_btn.set_css_classes(&["suggested-action", "pill"]);
                    connect_btn.set_valign(gtk4::Align::Center);
                    row.add_suffix(&connect_btn);

                    let agent_id = agent.agent_id.clone();
                    let token_c = token.clone();
                    let relay_url_c = relay_url.clone();
                    let profiles_c = profiles.clone();
                    let store_c = store.clone();
                    let vpn_c = vpn.clone();
                    let toast_c = toast.clone();

                    connect_btn.connect_clicked(move |_| {
                        // Pick the first profile; future: add profile picker popover.
                        let Some(profile) = profiles_c.first() else {
                            let t = Toast::new("No profiles — import an .ovpn first");
                            toast_c.add_toast(t);
                            return;
                        };
                        let config_path = store_c.borrow()
                            .config_path(&profile.id)
                            .map(|p| p.to_string_lossy().into_owned())
                            .unwrap_or_default();
                        let config_content = std::fs::read_to_string(&config_path)
                            .unwrap_or_default();

                        let tx = vpn_c.cmd_tx.clone();
                        let aid = agent_id.clone();
                        let tok = token_c.clone();
                        let rurl = relay_url_c.clone();
                        glib::spawn_future_local(async move {
                            tx.send(VpnCommand::ConnectRelay {
                                config_path,
                                config_content,
                                agent_id: aid,
                                org_token: tok,
                                relay_url: rurl,
                            }).await.ok();
                        });
                    });
                } else if agent.status == "connecting" {
                    let cancel_btn = Button::with_label("Cancel");
                    cancel_btn.set_css_classes(&["destructive-action", "pill"]);
                    cancel_btn.set_valign(gtk4::Align::Center);
                    row.add_suffix(&cancel_btn);

                    let vpn_c = vpn.clone();
                    cancel_btn.connect_clicked(move |_| {
                        let tx = vpn_c.cmd_tx.clone();
                        glib::spawn_future_local(async move {
                            tx.send(VpnCommand::Disconnect).await.ok();
                        });
                    });
                }

                list.append(&row);
            }

            // If an agent is already connected and we have no active relay flow
            // (e.g. fresh app open), infer Connected state from the agent list.
            if !any_busy {
                if let Some(agent) = agents.iter().find(|a| a.status == "connected") {
                    status_label.set_text(&format!("Agent {} tunnel is up.", agent.hostname));
                    status_label.set_visible(true);
                    disconnect_btn.set_visible(true);
                }
            }
        });
    }

    fn rebuild_agent_rows(&self) {
        // Lightweight rebuild — just remove connect buttons when busy.
        // Full rebuild happens in refresh_agents.
        self.refresh_agents();
    }
}
