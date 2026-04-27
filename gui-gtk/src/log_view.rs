// SPDX-License-Identifier: LGPL-2.1-or-later
use gtk4::prelude::*;
use gtk4::{Box as GtkBox, Button, Label, Orientation, ScrolledWindow, TextBuffer, TextView};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

const MAX_LINES: usize = 200;

pub struct LogView {
    pub widget: GtkBox,
    buffer: TextBuffer,
    lines: Rc<RefCell<VecDeque<String>>>,
    scrolled: ScrolledWindow,
}

impl LogView {
    pub fn new() -> Self {
        let root = GtkBox::new(Orientation::Vertical, 0);
        root.set_margin_start(8);
        root.set_margin_end(8);
        root.set_margin_top(8);
        root.set_margin_bottom(8);

        // Header row
        let header_row = GtkBox::new(Orientation::Horizontal, 0);

        let label = Label::new(Some("VPN Log"));
        label.set_css_classes(&["heading"]);
        label.set_hexpand(true);
        label.set_xalign(0.0);
        header_row.append(&label);

        let copy_btn = Button::with_label("Copy");
        copy_btn.set_css_classes(&["flat"]);
        header_row.append(&copy_btn);

        let clear_btn = Button::with_label("Clear");
        clear_btn.set_css_classes(&["flat"]);
        header_row.append(&clear_btn);

        root.append(&header_row);

        // Log text view
        let buffer = TextBuffer::new(None);
        let text_view = TextView::with_buffer(&buffer);
        text_view.set_editable(false);
        text_view.set_monospace(true);
        text_view.set_css_classes(&["log-view"]);
        text_view.set_left_margin(8);
        text_view.set_right_margin(8);
        text_view.set_top_margin(8);
        text_view.set_bottom_margin(8);
        text_view.set_wrap_mode(gtk4::WrapMode::Char);

        let scrolled = ScrolledWindow::new();
        scrolled.set_vexpand(true);
        scrolled.set_child(Some(&text_view));
        root.append(&scrolled);

        let lines: Rc<RefCell<VecDeque<String>>> = Rc::new(RefCell::new(VecDeque::new()));

        // Copy button
        {
            let buffer_c = buffer.clone();
            copy_btn.connect_clicked(move |btn| {
                let text = buffer_c
                    .text(&buffer_c.start_iter(), &buffer_c.end_iter(), false)
                    .to_string();
                let clipboard = btn.clipboard();
                clipboard.set_text(&text);
            });
        }

        // Clear button
        {
            let buffer_c = buffer.clone();
            let lines_c = lines.clone();
            clear_btn.connect_clicked(move |_| {
                buffer_c.set_text("");
                lines_c.borrow_mut().clear();
            });
        }

        Self { widget: root, buffer, lines, scrolled }
    }

    pub fn append_line(&self, line: &str) {
        let mut lines = self.lines.borrow_mut();
        lines.push_back(line.to_string());
        while lines.len() > MAX_LINES {
            lines.pop_front();
        }
        let text = lines
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join("\n");
        self.buffer.set_text(&text);

        // Auto-scroll to bottom
        let scrolled = self.scrolled.clone();
        gtk4::glib::idle_add_local_once(move || {
            let adj = scrolled.vadjustment();
            adj.set_value(adj.upper() - adj.page_size());
        });
    }
}
