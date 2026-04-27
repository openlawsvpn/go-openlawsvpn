// SPDX-License-Identifier: LGPL-2.1-or-later
use crate::connection::Profile;
use std::path::PathBuf;
use uuid::Uuid;

pub struct ProfileStore {
    base_dir: PathBuf,
}

impl ProfileStore {
    pub fn new() -> Self {
        let base = dirs_next();
        std::fs::create_dir_all(&base).ok();
        Self { base_dir: base }
    }

    pub fn list(&self) -> Vec<Profile> {
        let mut profiles = Vec::new();
        let Ok(entries) = std::fs::read_dir(&self.base_dir) else {
            return profiles;
        };
        for entry in entries.flatten() {
            let meta_path = entry.path().join("meta.json");
            if let Ok(data) = std::fs::read_to_string(&meta_path) {
                if let Ok(p) = serde_json::from_str::<Profile>(&data) {
                    profiles.push(p);
                }
            }
        }
        profiles.sort_by(|a, b| a.created_at.cmp(&b.created_at));
        profiles
    }

    pub fn import(&mut self, name: &str, content: &str) -> String {
        let id = Uuid::new_v4().to_string();
        let dir = self.base_dir.join(&id);
        std::fs::create_dir_all(&dir).ok();

        let config_path = dir.join("config.ovpn");
        std::fs::write(&config_path, content).ok();
        set_private(&config_path);

        let profile = Profile {
            id: id.clone(),
            name: name.to_string(),
            created_at: chrono_now(),
        };
        let meta = serde_json::to_string(&profile).unwrap_or_default();
        std::fs::write(dir.join("meta.json"), meta).ok();

        id
    }

    pub fn delete(&mut self, id: &str) {
        let dir = self.base_dir.join(id);
        std::fs::remove_dir_all(dir).ok();
    }

    pub fn config_path(&self, id: &str) -> Option<PathBuf> {
        let p = self.base_dir.join(id).join("config.ovpn");
        p.exists().then_some(p)
    }
}

fn dirs_next() -> PathBuf {
    // $XDG_DATA_HOME/openlawsvpn/profiles  or  ~/.local/share/openlawsvpn/profiles
    let base = std::env::var("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
            PathBuf::from(home).join(".local/share")
        });
    base.join("openlawsvpn/profiles")
}

fn set_private(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path) {
        let mut perms = meta.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(path, perms).ok();
    }
}

fn chrono_now() -> String {
    // Simple ISO-8601 timestamp without pulling in chrono
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{}", secs)
}
