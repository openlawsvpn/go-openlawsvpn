// SPDX-License-Identifier: LGPL-2.1-or-later
#[derive(Debug, Clone, PartialEq)]
pub enum ConnectionState {
    Idle,
    Connecting,
    WaitingSaml,
    Connected { server_ip: String, assigned_ip: String },
    Disconnecting,
    NeedReauth { reason: String },
    Error { message: String },
}

impl ConnectionState {
    pub fn is_busy(&self) -> bool {
        matches!(self, Self::Connecting | Self::WaitingSaml | Self::Disconnecting)
    }

    pub fn status_text(&self) -> Option<String> {
        match self {
            Self::Idle => None,
            Self::Connecting => Some("Connecting…".into()),
            Self::WaitingSaml => Some("Waiting for SAML login…".into()),
            Self::Connected { .. } => Some("● Connected".into()),
            Self::Disconnecting => Some("Disconnecting…".into()),
            Self::NeedReauth { reason } if reason.is_empty() =>
                Some("Session expired — tap Connect to re-authenticate".into()),
            Self::NeedReauth { reason } => Some(reason.clone()),
            Self::Error { message } => Some(format!("Error: {}", message)),
        }
    }

    pub fn show_spinner(&self) -> bool {
        matches!(self, Self::Connecting | Self::WaitingSaml | Self::Disconnecting)
    }

    pub fn button_label(&self) -> &'static str {
        match self {
            Self::Connected { .. } | Self::Disconnecting => "Disconnect",
            _ => "Connect",
        }
    }
}
