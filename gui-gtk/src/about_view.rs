// SPDX-License-Identifier: LGPL-2.1-or-later
use gtk4::prelude::*;
use gtk4::{Box as GtkBox, Button, Label, Orientation};
use libadwaita::prelude::*;
use libadwaita::AboutDialog;

pub struct AboutView {
    pub widget: GtkBox,
}

impl AboutView {
    pub fn new() -> Self {
        let root = GtkBox::new(Orientation::Vertical, 16);
        root.set_valign(gtk4::Align::Center);
        root.set_halign(gtk4::Align::Center);
        root.set_vexpand(true);
        root.set_margin_start(24);
        root.set_margin_end(24);
        root.set_margin_top(24);
        root.set_margin_bottom(24);

        let name_label = Label::new(Some("openlawsvpn"));
        name_label.set_css_classes(&["title-1"]);

        let version_label = Label::new(Some(concat!("Version ", env!("CARGO_PKG_VERSION"))));
        version_label.set_css_classes(&["dim-label"]);

        let desc_label = Label::new(Some(
            "OpenVPN 3 client with SAML/SSO support\nfor enterprise and cloud VPN access.",
        ));
        desc_label.set_justify(gtk4::Justification::Center);
        desc_label.set_wrap(true);

        let details_btn = Button::with_label("Licenses & Credits");
        details_btn.set_css_classes(&["pill"]);
        details_btn.set_halign(gtk4::Align::Center);

        root.append(&name_label);
        root.append(&version_label);
        root.append(&desc_label);
        root.append(&details_btn);

        details_btn.connect_clicked(|btn| {
            let dialog = AboutDialog::new();
            dialog.set_application_name("openlawsvpn");
            dialog.set_version(env!("CARGO_PKG_VERSION"));
            dialog.set_comments("OpenVPN 3 client with SAML/SSO support.");
            dialog.set_website("https://github.com/openlawsvpn/openlawsvpn");
            dialog.set_license_type(gtk4::License::Lgpl21);
            dialog.set_developers(&["openlawsvpn contributors"]);
            dialog.add_legal_section(
                "openvpn3-core",
                Some("AGPL-3.0-or-later — https://github.com/OpenVPN/openvpn3"),
                gtk4::License::Custom,
                None,
            );
            dialog.add_legal_section(
                "ASIO",
                Some("Boost Software License 1.0 — https://github.com/chriskohlhoff/asio"),
                gtk4::License::Custom,
                None,
            );
            dialog.add_legal_section(
                "OpenSSL",
                Some("Apache License 2.0 — https://github.com/openssl/openssl"),
                gtk4::License::Custom,
                None,
            );
            dialog.add_legal_section(
                "LZ4",
                Some("BSD 2-Clause — https://github.com/lz4/lz4"),
                gtk4::License::Custom,
                None,
            );

            let parent = btn.root().and_downcast::<gtk4::Window>();
            dialog.present(parent.as_ref());
        });

        Self { widget: root }
    }
}
