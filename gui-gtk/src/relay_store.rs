// SPDX-License-Identifier: LGPL-2.1-or-later
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const DEFAULT_RELAY_URL: &str = "https://api.relay.openlawsvpn.com/api/v1";

#[derive(Clone, Serialize, Deserialize)]
pub struct RelaySettings {
    #[serde(default)]
    pub org_token: String,
    // relay_url is always the production default; not user-configurable.
    #[serde(skip)]
    pub relay_url: String,
}

impl Default for RelaySettings {
    fn default() -> Self {
        Self {
            org_token: String::new(),
            relay_url: DEFAULT_RELAY_URL.to_string(),
        }
    }
}

impl RelaySettings {
    pub fn load() -> Self {
        let mut s: Self = std::fs::read_to_string(settings_path())
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        s.relay_url = std::env::var("OPENLAWSVPN_RELAY_URL")
            .unwrap_or_else(|_| DEFAULT_RELAY_URL.to_string());
        s
    }

    pub fn save(&self) {
        let path = settings_path();
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).ok();
        }
        if let Ok(json) = serde_json::to_string_pretty(self) {
            std::fs::write(path, json).ok();
        }
    }
}

fn settings_path() -> PathBuf {
    let base = std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/tmp".into()))
                .join(".config")
        });
    base.join("openlawsvpn/relay.json")
}
