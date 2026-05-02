// SPDX-License-Identifier: LGPL-2.1-or-later
//
// VPN service layer — talks to openlawsvpn-daemon over D-Bus (zbus).

use futures_channel::mpsc::{self, UnboundedReceiver, UnboundedSender};
use futures_util::StreamExt as _;
use zbus::{proxy, Connection};

// ── Public event/command types ───────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum VpnEvent {
    /// State changed; profile_path is non-empty when daemon has an active connection.
    StateChanged { state: VpnState, profile_path: String },
    LogLine(String),
    StatsUpdate { bytes_sent: u64, bytes_recv: u64, uptime_secs: u64 },
    /// Emitted immediately before a relay ConnectRelay call so the UI can route
    /// subsequent Connecting/WaitingSaml states to the relay screen.
    RelayFlowStarted,
}

#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)]
pub enum VpnState {
    Idle,
    Connecting,
    WaitingSaml { saml_url: String },
    Connected { server_ip: String, assigned_ip: String },
    Disconnecting,
    NeedReauth,
    Error(String),
    /// Relay: credentials delivered to relay API, remote agent is executing Phase 2.
    RelayDelivering { agent_id: String },
    /// Relay: remote agent has the tunnel up (this machine is NOT tunnelled).
    RelayConnected { agent_id: String },
}

#[derive(Debug)]
#[allow(dead_code)]
pub enum VpnCommand {
    Connect { config_path: String, config_content: String },
    ConnectRelay {
        config_path: String,
        config_content: String,
        agent_id: String,
        org_token: String,
        relay_url: String,
    },
    Disconnect,
    QueryStatus,
}

// ── D-Bus proxy ───────────────────────────────────────────────────────────────

#[proxy(
    interface = "com.openlawsvpn.Daemon",
    default_service = "com.openlawsvpn.Daemon",
    default_path = "/com/openlawsvpn/Daemon"
)]
trait VpnDaemon {
    #[zbus(name = "Connect")]
    fn connect(&self, profile_path: &str, profile_content: &str) -> zbus::Result<()>;
    #[zbus(name = "ConnectRelay")]
    fn connect_relay(
        &self,
        profile_path: &str,
        profile_content: &str,
        agent_id: &str,
        org_token: &str,
        relay_base_url: &str,
    ) -> zbus::Result<()>;
    #[zbus(name = "Disconnect")]
    fn disconnect(&self) -> zbus::Result<()>;
    #[zbus(name = "Status")]
    fn status(&self) -> zbus::Result<(String, String, String, String)>;

    #[zbus(signal, name = "StateChanged")]
    fn state_changed(&self, state: &str, server_ip: &str, assigned_ip: &str) -> zbus::Result<()>;
    #[zbus(signal, name = "LogLine")]
    fn log_line(&self, line: &str) -> zbus::Result<()>;
    #[zbus(signal, name = "StatsUpdate")]
    fn stats_update(&self, bytes_sent: u64, bytes_recv: u64, uptime_secs: u64) -> zbus::Result<()>;
    #[zbus(signal, name = "SAMLRequired")]
    fn saml_required(&self, url: &str) -> zbus::Result<()>;
}

// ── VpnService ────────────────────────────────────────────────────────────────

pub struct VpnService {
    pub cmd_tx: tokio::sync::mpsc::Sender<VpnCommand>,
    pub rt_handle: tokio::runtime::Handle,
    event_rx: std::cell::RefCell<Option<UnboundedReceiver<VpnEvent>>>,
}

impl VpnService {
    pub fn new() -> Self {
        let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel::<VpnCommand>(8);
        let (event_tx, event_rx) = mpsc::unbounded::<VpnEvent>();
        let (handle_tx, handle_rx) = std::sync::mpsc::channel::<tokio::runtime::Handle>();

        std::thread::spawn(move || {
            service_thread(cmd_rx, event_tx, handle_tx);
        });

        let rt_handle = handle_rx.recv().expect("service thread did not send Handle");

        Self {
            cmd_tx,
            rt_handle,
            event_rx: std::cell::RefCell::new(Some(event_rx)),
        }
    }

    pub fn take_event_rx(&self) -> UnboundedReceiver<VpnEvent> {
        self.event_rx
            .borrow_mut()
            .take()
            .expect("take_event_rx() called more than once")
    }
}

// ── Background service thread ─────────────────────────────────────────────────

fn service_thread(
    mut cmd_rx: tokio::sync::mpsc::Receiver<VpnCommand>,
    event_tx: UnboundedSender<VpnEvent>,
    handle_tx: std::sync::mpsc::Sender<tokio::runtime::Handle>,
) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio rt");

    handle_tx.send(rt.handle().clone()).ok();

    rt.block_on(async move {
        let dbus_conn = match Connection::system().await {
            Ok(c) => c,
            Err(e) => {
                emit_state(&event_tx, VpnState::Error(
                    format!("Cannot connect to system bus: {e}"),
                ), String::new());
                return;
            }
        };

        // Query daemon state immediately so the GUI reflects any active connection.
        handle_query_status(&dbus_conn, &event_tx).await;

        while let Some(cmd) = cmd_rx.recv().await {
            match cmd {
                VpnCommand::Connect { config_path, config_content } => {
                    handle_connect(&dbus_conn, &event_tx, config_path, config_content, &mut cmd_rx).await;
                }
                VpnCommand::ConnectRelay { config_path, config_content, agent_id, org_token, relay_url } => {
                    event_tx.unbounded_send(VpnEvent::RelayFlowStarted).ok();
                    handle_connect_relay(
                        &dbus_conn, &event_tx,
                        config_path, config_content, agent_id, org_token, relay_url,
                        &mut cmd_rx,
                    ).await;
                }
                VpnCommand::Disconnect => {
                    let proxy = VpnDaemonProxy::new(&dbus_conn).await;
                    if let Ok(p) = proxy {
                        let _ = p.disconnect().await;
                    }
                    emit_state(&event_tx, VpnState::Idle, String::new());
                }
                VpnCommand::QueryStatus => {
                    handle_query_status(&dbus_conn, &event_tx).await;
                }
            }
        }
    });
}

async fn handle_query_status(dbus_conn: &Connection, event_tx: &UnboundedSender<VpnEvent>) {
    let proxy = match VpnDaemonProxy::new(dbus_conn).await {
        Ok(p) => p,
        Err(_) => {
            emit_state(event_tx, VpnState::Idle, String::new());
            return;
        }
    };
    match proxy.status().await {
        Ok((state_str, server_ip, assigned_ip, profile_path)) => {
            let state = parse_state(&state_str, &server_ip, &assigned_ip);
            emit_state(event_tx, state, profile_path);
        }
        Err(_) => {
            emit_state(event_tx, VpnState::Idle, String::new());
        }
    }
}

async fn handle_connect(
    dbus_conn: &Connection,
    event_tx: &UnboundedSender<VpnEvent>,
    config_path: String,
    config_content: String,
    cmd_rx: &mut tokio::sync::mpsc::Receiver<VpnCommand>,
) {
    let proxy = match VpnDaemonProxy::new(dbus_conn).await {
        Ok(p) => p,
        Err(e) => {
            emit_state(event_tx, VpnState::Error(
                format!("D-Bus proxy: {e} — is openlawsvpn-daemon running?"),
            ), String::new());
            return;
        }
    };

    let mut state_stream = match proxy.receive_state_changed().await {
        Ok(s) => s,
        Err(e) => { emit_state(event_tx, VpnState::Error(format!("subscribe StateChanged: {e}")), String::new()); return; }
    };
    let mut log_stream = match proxy.receive_log_line().await {
        Ok(s) => s,
        Err(e) => { emit_state(event_tx, VpnState::Error(format!("subscribe LogLine: {e}")), String::new()); return; }
    };
    let mut stats_stream = match proxy.receive_stats_update().await {
        Ok(s) => s,
        Err(e) => { emit_state(event_tx, VpnState::Error(format!("subscribe StatsUpdate: {e}")), String::new()); return; }
    };
    let mut saml_stream = match proxy.receive_saml_required().await {
        Ok(s) => s,
        Err(e) => { emit_state(event_tx, VpnState::Error(format!("subscribe SAMLRequired: {e}")), String::new()); return; }
    };

    if let Err(e) = proxy.connect(&config_path, &config_content).await {
        emit_state(event_tx, VpnState::Error(format!("daemon Connect: {e}")), String::new());
        return;
    }

    loop {
        tokio::select! {
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(VpnCommand::Disconnect) => {
                        emit_state(event_tx, VpnState::Disconnecting, String::new());
                        if let Err(e) = proxy.disconnect().await {
                            event_tx.unbounded_send(VpnEvent::LogLine(
                                format!("daemon Disconnect: {e}")
                            )).ok();
                        }
                        emit_state(event_tx, VpnState::Idle, String::new());
                        return;
                    }
                    Some(other) => { drop(other); }
                    None => return,
                }
            }
            Some(sig) = state_stream.next() => {
                if let Ok(args) = sig.args() {
                    let state = parse_state(args.state, args.server_ip, args.assigned_ip);
                    let terminal = matches!(state, VpnState::Idle | VpnState::Error(_));
                    emit_state(event_tx, state, config_path.clone());
                    if terminal { return; }
                }
            }
            Some(sig) = log_stream.next() => {
                if let Ok(args) = sig.args() {
                    event_tx.unbounded_send(VpnEvent::LogLine(args.line.to_string())).ok();
                }
            }
            Some(sig) = stats_stream.next() => {
                if let Ok(args) = sig.args() {
                    event_tx.unbounded_send(VpnEvent::StatsUpdate {
                        bytes_sent: args.bytes_sent,
                        bytes_recv: args.bytes_recv,
                        uptime_secs: args.uptime_secs,
                    }).ok();
                }
            }
            Some(sig) = saml_stream.next() => {
                if let Ok(args) = sig.args() {
                    emit_state(event_tx, VpnState::WaitingSaml {
                        saml_url: args.url.to_string(),
                    }, config_path.clone());
                }
            }
            else => break,
        }
    }
}

async fn handle_connect_relay(
    dbus_conn: &Connection,
    event_tx: &UnboundedSender<VpnEvent>,
    config_path: String,
    config_content: String,
    agent_id: String,
    org_token: String,
    relay_url: String,
    cmd_rx: &mut tokio::sync::mpsc::Receiver<VpnCommand>,
) {
    let proxy = match VpnDaemonProxy::new(dbus_conn).await {
        Ok(p) => p,
        Err(e) => {
            emit_state(event_tx, VpnState::Error(
                format!("D-Bus proxy: {e} — is openlawsvpn-daemon running?"),
            ), String::new());
            return;
        }
    };

    let mut state_stream = match proxy.receive_state_changed().await {
        Ok(s) => s,
        Err(e) => { emit_state(event_tx, VpnState::Error(format!("subscribe StateChanged: {e}")), String::new()); return; }
    };
    let mut log_stream = match proxy.receive_log_line().await {
        Ok(s) => s,
        Err(e) => { emit_state(event_tx, VpnState::Error(format!("subscribe LogLine: {e}")), String::new()); return; }
    };
    let mut saml_stream = match proxy.receive_saml_required().await {
        Ok(s) => s,
        Err(e) => { emit_state(event_tx, VpnState::Error(format!("subscribe SAMLRequired: {e}")), String::new()); return; }
    };

    if let Err(e) = proxy.connect_relay(
        &config_path, &config_content, &agent_id, &org_token, &relay_url,
    ).await {
        emit_state(event_tx, VpnState::Error(format!("daemon ConnectRelay: {e}")), String::new());
        return;
    }

    loop {
        tokio::select! {
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(VpnCommand::Disconnect) => {
                        if let Err(e) = proxy.disconnect().await {
                            event_tx.unbounded_send(VpnEvent::LogLine(
                                format!("daemon Disconnect: {e}")
                            )).ok();
                        }
                        emit_state(event_tx, VpnState::Idle, String::new());
                        return;
                    }
                    Some(other) => { drop(other); }
                    None => return,
                }
            }
            Some(sig) = state_stream.next() => {
                if let Ok(args) = sig.args() {
                    let state = parse_relay_state(args.state, args.server_ip);
                    let terminal = matches!(state,
                        VpnState::Idle | VpnState::Error(_) | VpnState::RelayConnected { .. }
                    );
                    emit_state(event_tx, state, config_path.clone());
                    if terminal { return; }
                }
            }
            Some(sig) = log_stream.next() => {
                if let Ok(args) = sig.args() {
                    event_tx.unbounded_send(VpnEvent::LogLine(args.line.to_string())).ok();
                }
            }
            Some(sig) = saml_stream.next() => {
                if let Ok(args) = sig.args() {
                    emit_state(event_tx, VpnState::WaitingSaml {
                        saml_url: args.url.to_string(),
                    }, config_path.clone());
                }
            }
            else => break,
        }
    }
}

fn parse_state(state: &str, server_ip: &str, assigned_ip: &str) -> VpnState {
    match state {
        "idle"              => VpnState::Idle,
        "connecting"        => VpnState::Connecting,
        "waiting_saml"      => VpnState::WaitingSaml { saml_url: String::new() },
        "connected"         => VpnState::Connected {
            server_ip: server_ip.to_string(),
            assigned_ip: assigned_ip.to_string(),
        },
        "disconnecting"     => VpnState::Disconnecting,
        "error"             => VpnState::Error(assigned_ip.to_string()),
        "relay_delivering"  => VpnState::RelayDelivering { agent_id: server_ip.to_string() },
        "relay_connected"   => VpnState::RelayConnected { agent_id: server_ip.to_string() },
        other               => VpnState::Error(format!("unknown daemon state: {other}")),
    }
}

// parse_relay_state maps daemon state strings during a relay flow.
// server_ip carries agent_id for relay-specific states.
fn parse_relay_state(state: &str, agent_id: &str) -> VpnState {
    match state {
        "idle"             => VpnState::Idle,
        "connecting"       => VpnState::Connecting,
        "waiting_saml"     => VpnState::WaitingSaml { saml_url: String::new() },
        "disconnecting"    => VpnState::Disconnecting,
        "relay_delivering" => VpnState::RelayDelivering { agent_id: agent_id.to_string() },
        "relay_connected"  => VpnState::RelayConnected { agent_id: agent_id.to_string() },
        "error"            => VpnState::Error(agent_id.to_string()),
        other              => VpnState::Error(format!("unknown daemon state: {other}")),
    }
}

fn emit_state(tx: &UnboundedSender<VpnEvent>, state: VpnState, profile_path: String) {
    tx.unbounded_send(VpnEvent::StateChanged { state, profile_path }).ok();
}
