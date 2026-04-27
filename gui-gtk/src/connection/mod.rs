// SPDX-License-Identifier: LGPL-2.1-or-later
pub mod profile;
pub mod state;

pub use profile::Profile;
pub use state::ConnectionState;

use gtk4::prelude::*;
use gtk4::{
    Box as GtkBox, Button, FileDialog, Label, ListBox, Orientation,
    ScrolledWindow, SelectionMode, Spinner,
};
use libadwaita::prelude::*;
use libadwaita::{ActionRow, Toast, ToastOverlay};

use std::cell::RefCell;
use std::rc::Rc;

use crate::profile_store::ProfileStore;
use crate::vpn_service::{VpnCommand, VpnService};

pub struct ConnectionScreen {
    pub widget: GtkBox,
    pub toast_overlay: ToastOverlay,
    store: Rc<RefCell<ProfileStore>>,
    vpn: Rc<VpnService>,
    list_box: ListBox,
    empty_label: Label,
    scrolled: ScrolledWindow,
    active_id: Rc<RefCell<Option<String>>>,
    state: Rc<RefCell<ConnectionState>>,
}

impl ConnectionScreen {
    pub fn new(
        store: Rc<RefCell<ProfileStore>>,
        vpn: Rc<VpnService>,
    ) -> Rc<RefCell<Self>> {
        let root = GtkBox::new(Orientation::Vertical, 0);

        let header = Label::new(Some("Profiles"));
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

        let empty_label = Label::new(Some(
            "No VPN profiles yet\n\nImport an .ovpn file to get started.",
        ));
        empty_label.set_css_classes(&["dim-label"]);
        empty_label.set_justify(gtk4::Justification::Center);
        empty_label.set_vexpand(true);
        empty_label.set_valign(gtk4::Align::Center);
        content.append(&empty_label);

        let scrolled = ScrolledWindow::new();
        scrolled.set_vexpand(true);
        scrolled.set_visible(false);
        scrolled.set_policy(gtk4::PolicyType::Never, gtk4::PolicyType::Automatic);

        let list_box = ListBox::new();
        list_box.set_selection_mode(SelectionMode::None);
        list_box.set_css_classes(&["boxed-list"]);
        list_box.set_margin_start(16);
        list_box.set_margin_end(16);
        list_box.set_margin_top(8);
        list_box.set_margin_bottom(8);
        scrolled.set_child(Some(&list_box));
        content.append(&scrolled);

        let import_btn = Button::with_label("+ Add Profile");
        import_btn.set_css_classes(&["pill"]);
        import_btn.set_margin_start(16);
        import_btn.set_margin_end(16);
        import_btn.set_margin_top(8);
        import_btn.set_margin_bottom(16);
        content.append(&import_btn);

        let screen = Rc::new(RefCell::new(Self {
            widget: root,
            toast_overlay,
            store,
            vpn,
            list_box,
            empty_label,
            scrolled,
            active_id: Rc::new(RefCell::new(None)),
            state: Rc::new(RefCell::new(ConnectionState::Idle)),
        }));

        {
            let screen_clone = screen.clone();
            import_btn.connect_clicked(move |btn| {
                let win = btn.root().and_downcast::<gtk4::Window>();
                Self::open_file_picker(win, screen_clone.clone());
            });
        }

        screen.borrow().refresh_list();
        screen
    }

    /// Called from main.rs when a VpnEvent::StateChanged arrives.
    pub fn set_state(&mut self, state: ConnectionState) {
        *self.state.borrow_mut() = state;
        self.refresh_list();
    }

    fn refresh_list(&self) {
        while let Some(child) = self.list_box.first_child() {
            self.list_box.remove(&child);
        }

        let profiles = self.store.borrow().list();

        if profiles.is_empty() {
            self.empty_label.set_visible(true);
            self.scrolled.set_visible(false);
        } else {
            self.empty_label.set_visible(false);
            self.scrolled.set_visible(true);

            let active_id = self.active_id.clone();
            let state = self.state.clone();
            let vpn = self.vpn.clone();
            let store = self.store.clone();
            let toast_overlay = self.toast_overlay.clone();

            // any_busy: disable all Connect buttons while a connection is in progress
            let any_busy = state.borrow().is_busy();

            for profile in &profiles {
                let row = Self::build_profile_row(
                    profile,
                    &active_id,
                    &state,
                    any_busy,
                    vpn.clone(),
                    store.clone(),
                    toast_overlay.clone(),
                );
                self.list_box.append(&row);
            }
        }
    }

    fn build_profile_row(
        profile: &Profile,
        active_id: &Rc<RefCell<Option<String>>>,
        state: &Rc<RefCell<ConnectionState>>,
        any_busy: bool,
        vpn: Rc<VpnService>,
        store: Rc<RefCell<ProfileStore>>,
        toast_overlay: ToastOverlay,
    ) -> ActionRow {
        let row = ActionRow::new();
        row.set_title(&profile.name);
        row.add_css_class("profile-card");

        let is_active = active_id.borrow().as_deref() == Some(&profile.id);
        let current_state = state.borrow().clone();

        // Status subtitle
        if is_active {
            if let Some(text) = current_state.status_text() {
                row.set_subtitle(&text);
            }
        }

        // Spinner
        let spinner = Spinner::new();
        spinner.set_visible(is_active && current_state.show_spinner());
        if spinner.is_visible() {
            spinner.start();
        }
        row.add_prefix(&spinner);

        // Action button
        let btn_label = if is_active { current_state.button_label() } else { "Connect" };
        let btn = Button::with_label(btn_label);
        btn.set_css_classes(&["suggested-action", "pill"]);
        btn.set_valign(gtk4::Align::Center);

        // Disable when busy (another profile connecting, or self is mid-transition)
        let self_busy = is_active && current_state.is_busy();
        btn.set_sensitive(!any_busy || (is_active && matches!(current_state,
            ConnectionState::Connected { .. } | ConnectionState::NeedReauth { .. } | ConnectionState::Error { .. }
        )));
        if self_busy {
            btn.set_sensitive(false);
        }

        row.add_suffix(&btn);

        // Button click: connect or disconnect
        {
            let active_id = active_id.clone();
            let state = state.clone();
            let profile_id = profile.id.clone();
            let config_path = store.borrow()
                .config_path(&profile.id)
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default();
            let vpn = vpn.clone();

            btn.connect_clicked(move |_| {
                let is_active = active_id.borrow().as_deref() == Some(&profile_id);
                let cur = state.borrow().clone();

                if is_active && matches!(cur, ConnectionState::Connected { .. }) {
                    // Disconnect
                    let tx = vpn.cmd_tx.clone();
                    gtk4::glib::spawn_future_local(async move {
                        tx.send(VpnCommand::Disconnect).await.ok();
                    });
                    *active_id.borrow_mut() = None;
                } else {
                    // Connect
                    *active_id.borrow_mut() = Some(profile_id.clone());
                    let tx = vpn.cmd_tx.clone();
                    let path = config_path.clone();
                    gtk4::glib::spawn_future_local(async move {
                        tx.send(VpnCommand::Connect { config_path: path })
                            .await
                            .ok();
                    });
                }
            });
        }

        // Right-click → Delete context menu
        {
            let profile_id = profile.id.clone();
            let profile_name = profile.name.clone();
            let store = store.clone();
            let toast_overlay = toast_overlay.clone();
            // Only allow delete when not actively connected on this profile
            let deletable = !(is_active && matches!(current_state,
                ConnectionState::Connected { .. } | ConnectionState::Connecting | ConnectionState::WaitingSaml
            ));

            if deletable {
                let gesture = gtk4::GestureClick::new();
                gesture.set_button(3);
                gesture.connect_pressed(move |g, _, x, y| {
                    let widget = g.widget();
                    let Some(widget) = widget else { return };
                    let popover = gtk4::PopoverMenu::from_model(None::<&gtk4::gio::MenuModel>);
                    let menu_box = GtkBox::new(Orientation::Vertical, 4);
                    menu_box.set_margin_start(4);
                    menu_box.set_margin_end(4);
                    menu_box.set_margin_top(4);
                    menu_box.set_margin_bottom(4);
                    let delete_btn = Button::with_label("Delete");
                    delete_btn.set_css_classes(&["flat", "delete-action"]);
                    menu_box.append(&delete_btn);
                    popover.set_child(Some(&menu_box));
                    popover.set_parent(&widget);
                    popover.set_pointing_to(Some(&gtk4::gdk::Rectangle::new(
                        x as i32, y as i32, 1, 1,
                    )));

                    let store = store.clone();
                    let profile_id = profile_id.clone();
                    let profile_name = profile_name.clone();
                    let toast_overlay = toast_overlay.clone();
                    let popover_clone = popover.clone();
                    delete_btn.connect_clicked(move |_| {
                        store.borrow_mut().delete(&profile_id);
                        let toast = Toast::new(&format!("Profile '{}' deleted.", profile_name));
                        toast_overlay.add_toast(toast);
                        popover_clone.popdown();
                    });

                    popover.popup();
                });
                row.add_controller(gesture);
            }
        }

        row
    }

    fn open_file_picker(
        parent: Option<gtk4::Window>,
        screen: Rc<RefCell<ConnectionScreen>>,
    ) {
        let dialog = FileDialog::new();
        dialog.set_title("Import .ovpn Profile");
        dialog.set_modal(true);

        let filter = gtk4::FileFilter::new();
        filter.set_name(Some("OpenVPN profiles (*.ovpn)"));
        filter.add_suffix("ovpn");
        let filters = gtk4::gio::ListStore::new::<gtk4::FileFilter>();
        filters.append(&filter);
        dialog.set_filters(Some(&filters));
        dialog.set_default_filter(Some(&filter));

        dialog.open(parent.as_ref(), gtk4::gio::Cancellable::NONE, move |result| {
            if let Ok(file) = result {
                let path = file.path().unwrap_or_default();
                let name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("profile")
                    .trim_end_matches(".ovpn")
                    .to_string();

                match std::fs::read_to_string(&path) {
                    Ok(content) => {
                        let s = screen.borrow();
                        s.store.borrow_mut().import(&name, &content);
                        let toast = Toast::new(&format!("Profile '{}' imported.", name));
                        s.toast_overlay.add_toast(toast);
                        drop(s);
                        screen.borrow().refresh_list();
                    }
                    Err(e) => {
                        let s = screen.borrow();
                        let toast = Toast::new(&format!("Import failed: {}", e));
                        s.toast_overlay.add_toast(toast);
                    }
                }
            }
        });
    }

    pub fn get_widget(&self) -> &GtkBox {
        &self.widget
    }
}
