use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::{Mutex, RwLock};
use rand::{RngCore, rngs::OsRng};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use p2p_signaling_client::SignalingSender;
use p2p_signaling_proto::*;
use p2p_stun::{StunClient, StunResponseRouter};
use p2p_turn::TurnCredentials;

use crate::candidate::{Candidate, gather_host_candidates};
use crate::config::{P2pConfig, TurnConfig};
use crate::dual_stack::DualStackSocket;
use crate::error::P2pError;
use crate::kcp_session::{KcpSession, classify_packet, PacketType};
use crate::negotiation;
use crate::punch;
use crate::stats::StatsSnapshot;

/// Connection lifecycle states.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionState {
    Idle,
    Registered,
    Gathering,
    Punching,
    KcpHandshake,
    Connected,
    Relayed,
    Reconnecting,
    Disconnected,
}

/// Callback types for connection events.
pub type StateCallback = Box<dyn Fn(&str, ConnectionState) + Send + Sync>;
pub type ReceiveCallback = Box<dyn Fn(&str, &[u8]) + Send + Sync>;
pub type IncomingCallback = Box<dyn Fn(&str) -> bool + Send + Sync>;

/// Reconnection bookkeeping for a peer. Stored separately from PeerConnection
/// so it survives connection cleanup during gathering timeouts.
struct ReconnectState {
    attempts: u32,
    was_connected: bool,
}

/// Manages all P2P connections.
pub struct ConnectionManager {
    config: P2pConfig,
    /// Dynamic TURN server configuration. Updated via set_turn_config().
    turn_config: Arc<RwLock<Option<TurnConfig>>>,
    socket: Arc<DualStackSocket>,
    signaling_tx: Arc<Mutex<Option<SignalingSender>>>,
    connections: Arc<Mutex<HashMap<String, PeerConnection>>>,
    peer_id: Arc<Mutex<Option<String>>>,

    /// M4: Reverse index from KCP conv_id to peer_id for O(1) packet routing.
    /// Updated when KCP sessions are created/destroyed.
    conv_id_index: Arc<Mutex<HashMap<u32, String>>>,

    /// Routes STUN/TURN responses from the recv loop to waiting callers.
    stun_router: Arc<StunResponseRouter>,

    // Callbacks
    state_cb: Arc<Mutex<Option<StateCallback>>>,
    receive_cb: Arc<Mutex<Option<ReceiveCallback>>>,
    incoming_cb: Arc<Mutex<Option<IncomingCallback>>>,

    // Background tasks
    recv_task: Mutex<Option<JoinHandle<()>>>,
    signaling_task: Mutex<Option<JoinHandle<()>>>,
    /// H7: Handle to the WebSocket I/O task for the signaling client.
    signaling_io_task: Mutex<Option<JoinHandle<()>>>,
    /// Background health monitor task (keepalive + dead detection).
    health_task: Mutex<Option<JoinHandle<()>>>,
    /// Set to true during shutdown to prevent reconnection attempts.
    shutting_down: portable_atomic::AtomicBool,
    /// Reconnection state per peer (survives PeerConnection removal).
    reconnect_state: Arc<Mutex<HashMap<String, ReconnectState>>>,
}

/// State for a single peer connection.
struct PeerConnection {
    state: ConnectionState,
    session_id: String,
    session_hash: [u8; 4],
    is_initiator: bool,
    /// Whether a reverse connection attempt has already been tried.
    reverse_attempted: bool,
    local_candidates: Vec<Candidate>,
    remote_candidates: Vec<Candidate>,
    kcp_session: Option<Arc<KcpSession>>,
    remote_addr: Option<SocketAddr>,
    /// Channel to feed probe packets to the punch engine for this connection.
    probe_tx: Option<mpsc::UnboundedSender<(Vec<u8>, SocketAddr)>>,
    /// Channel to feed late-arriving candidates to the running punch engine.
    candidate_tx: Option<mpsc::UnboundedSender<Candidate>>,
    /// Handle for the punch task (so we can abort it if needed).
    punch_task: Option<JoinHandle<()>>,
    /// Whether the remote peer has answered (accepted the connection).
    answer_received: bool,
    /// TURN allocation for relay fallback (if configured).
    turn_allocation: Option<p2p_turn::TurnAllocation>,
    /// TURN channel number assigned for this peer.
    turn_channel: Option<u16>,
    /// Per-connect punch timeout override. None = use default from config.
    punch_timeout_override: Option<Duration>,
    /// Skip hole punching entirely and go straight to TURN relay.
    turn_only: bool,
    /// Whether automatic P2P retry is enabled while in Relayed state.
    p2p_retry_enabled: bool,
    /// Handle for the P2P retry background task (aborted on disable/disconnect).
    p2p_retry_task: Option<JoinHandle<()>>,
}

impl ConnectionManager {
    /// Create a new ConnectionManager with the given configuration.
    pub async fn new(config: P2pConfig) -> Result<Arc<Self>, P2pError> {
        let socket = Arc::new(DualStackSocket::bind(0, config.enable_ipv6).await?);
        let stun_router = Arc::new(StunResponseRouter::new());

        let manager = Arc::new(Self {
            config,
            turn_config: Arc::new(RwLock::new(None)),
            socket,
            signaling_tx: Arc::new(Mutex::new(None)),
            connections: Arc::new(Mutex::new(HashMap::new())),
            peer_id: Arc::new(Mutex::new(None)),
            conv_id_index: Arc::new(Mutex::new(HashMap::new())),
            stun_router,
            state_cb: Arc::new(Mutex::new(None)),
            receive_cb: Arc::new(Mutex::new(None)),
            incoming_cb: Arc::new(Mutex::new(None)),
            recv_task: Mutex::new(None),
            signaling_task: Mutex::new(None),
            signaling_io_task: Mutex::new(None),
            health_task: Mutex::new(None),
            shutting_down: portable_atomic::AtomicBool::new(false),
            reconnect_state: Arc::new(Mutex::new(HashMap::new())),
        });

        // Start the UDP receive loop
        manager.start_recv_loop();

        // Start the health monitor (keepalive + dead connection detection)
        manager.start_health_monitor();

        Ok(manager)
    }

    /// Dynamically set or clear the TURN server configuration.
    ///
    /// If `config` is `Some`, new connections will attempt TURN relay allocation
    /// as a fallback when hole punching fails. If `None`, TURN is disabled.
    /// Only affects new connections; existing connections are not affected.
    pub fn set_turn_config(&self, config: Option<TurnConfig>) {
        let mut guard = self.turn_config.write();
        if let Some(ref c) = config {
            tracing::info!("TURN config updated: server={}", c.server_addr);
        } else {
            tracing::info!("TURN config cleared (disabled)");
        }
        *guard = config;
    }

    /// Connect to the signaling server and register with the given peer ID.
    pub async fn register(self: &Arc<Self>, peer_id: &str) -> Result<(), P2pError> {
        let mut client =
            p2p_signaling_client::SignalingClient::connect(&self.config.signaling_url).await?;
        client.register(peer_id).await?;

        *self.peer_id.lock() = Some(peer_id.to_string());

        // Split the client: sender stays in mutex, receiver goes to handler task.
        // The io_task handle is stored so we can abort it on shutdown.
        let (sender, receiver, io_task) = client.into_parts();
        *self.signaling_tx.lock() = Some(sender);
        *self.signaling_io_task.lock() = io_task;

        // Start the signaling message handler loop
        self.start_signaling_handler(receiver);

        tracing::info!("Registered as '{}'", peer_id);
        Ok(())
    }

    /// Initiate a connection to a remote peer.
    ///
    /// `punch_timeout` overrides the global punch timeout for this connection.
    /// `None` means use the default from config (15s).
    ///
    /// `turn_only` skips hole punching entirely: candidate gathering still runs
    /// (TURN allocation is needed), but once TURN is ready the connection goes
    /// straight to relay mode without attempting any probes.
    pub async fn connect(
        self: &Arc<Self>,
        remote_peer_id: &str,
        punch_timeout: Option<Duration>,
        turn_only: bool,
    ) -> Result<(), P2pError> {
        let session_id = uuid::Uuid::new_v4().to_string();
        let session_hash = punch::compute_session_hash(&session_id);

        // Send connect request via signaling
        {
            let signaling = self.signaling_tx.lock();
            let signaling = signaling.as_ref().ok_or(P2pError::NotConnected)?;
            signaling.send(SignalingMessage::ConnectRequest(ConnectRequestPayload {
                target_peer_id: remote_peer_id.to_string(),
                session_id: session_id.clone(),
            }))?;
        }

        // Create peer connection entry
        {
            let mut connections = self.connections.lock();
            connections.insert(
                remote_peer_id.to_string(),
                PeerConnection {
                    state: ConnectionState::Gathering,
                    session_id: session_id.clone(),
                    session_hash,
                    is_initiator: true,
                    reverse_attempted: false,
                    local_candidates: Vec::new(),
                    remote_candidates: Vec::new(),
                    kcp_session: None,
                    remote_addr: None,
                    probe_tx: None,
                    candidate_tx: None,
                    punch_task: None,
                    answer_received: false,
                    turn_allocation: None,
                    turn_channel: None,
                    punch_timeout_override: punch_timeout,
                    turn_only,
                    p2p_retry_enabled: false,
                    p2p_retry_task: None,
                },
            );
        }

        self.notify_state(remote_peer_id, ConnectionState::Gathering);

        // Send host candidates immediately (no I/O, instant)
        self.gather_and_send_candidates(remote_peer_id).await?;

        // Spawn background STUN/TURN gathering — results trickle in asynchronously
        self.spawn_reflexive_gathering(remote_peer_id);

        if !turn_only {
            // Try to start punching now that we have local host candidates.
            // If the remote Answer and candidates already arrived, punch starts immediately
            // without waiting for STUN results.
            self.try_start_punching(remote_peer_id).await;
        }

        // Spawn a gathering timeout watchdog: if we're still in Gathering after
        // 10 seconds (waiting for Answer or remote candidates), fail the connection.
        // For turn_only mode, this ensures we don't wait forever for TURN allocation.
        self.spawn_gathering_timeout(remote_peer_id);

        Ok(())
    }

    /// Send data to a connected peer.
    pub fn send(&self, remote_peer_id: &str, data: &[u8]) -> Result<(), P2pError> {
        // Clone session Arc under lock, then release lock before calling send().
        // This avoids holding `connections` lock during the entire KCP encode +
        // pipeline processing, which would be a performance bottleneck and risk
        // lock ordering issues (connections -> kcp -> pipeline locks).
        let session = {
            let connections = self.connections.lock();
            let conn = connections
                .get(remote_peer_id)
                .ok_or_else(|| P2pError::PeerNotFound(remote_peer_id.to_string()))?;
            conn.kcp_session
                .as_ref()
                .ok_or(P2pError::NotConnected)?
                .clone()
        };

        // Frame as application data: [0x00][data...]
        let mut framed = Vec::with_capacity(1 + data.len());
        framed.push(negotiation::FRAME_APP_DATA);
        framed.extend_from_slice(data);
        session.send(&framed).map_err(P2pError::Kcp)
    }

    /// Disconnect from a specific peer.
    pub fn disconnect(&self, remote_peer_id: &str) {
        let mut connections = self.connections.lock();
        if let Some(mut conn) = connections.remove(remote_peer_id) {
            if let Some(h) = conn.punch_task.take() {
                h.abort();
            }
            if let Some(h) = conn.p2p_retry_task.take() {
                h.abort();
            }
            // M4: Remove conv_id index entry
            if let Some(session) = &conn.kcp_session {
                self.conv_id_index.lock().remove(&session.conv_id());
            }
            drop(connections);
            // Explicit disconnect clears reconnect state
            self.reconnect_state.lock().remove(remote_peer_id);
            self.notify_state(remote_peer_id, ConnectionState::Disconnected);
        }
    }

    /// Explicitly shut down the manager, aborting all background tasks and
    /// releasing all connections.
    ///
    /// This should be called before dropping the last `Arc<ConnectionManager>`
    /// to ensure that fire-and-forget tasks (STUN/TURN gathering, timeouts)
    /// don't keep the manager alive via `Arc` references.
    ///
    /// After shutdown, the manager is inert — recv loop and signaling handler
    /// are stopped, and all peer connections are removed.
    pub fn shutdown(&self) {
        // Signal all reconnection loops to stop
        self.shutting_down.store(true, Relaxed);
        // Abort tracked background tasks
        if let Some(h) = self.recv_task.lock().take() {
            h.abort();
        }
        if let Some(h) = self.signaling_task.lock().take() {
            h.abort();
        }
        // H7: Abort the signaling WebSocket I/O task
        if let Some(h) = self.signaling_io_task.lock().take() {
            h.abort();
        }
        // Abort health monitor
        if let Some(h) = self.health_task.lock().take() {
            h.abort();
        }
        // Drop the signaling sender to unblock any pending sends
        *self.signaling_tx.lock() = None;
        // M4: Clear the conv_id index
        self.conv_id_index.lock().clear();
        // Clean up all connections and abort punch tasks
        let mut connections = self.connections.lock();
        for (_, conn) in connections.iter_mut() {
            if let Some(h) = conn.punch_task.take() {
                h.abort();
            }
        }
        connections.clear();
    }

    pub fn set_state_callback(&self, cb: StateCallback) {
        *self.state_cb.lock() = Some(cb);
    }

    pub fn set_receive_callback(&self, cb: ReceiveCallback) {
        *self.receive_cb.lock() = Some(cb);
    }

    pub fn set_incoming_callback(&self, cb: IncomingCallback) {
        *self.incoming_cb.lock() = Some(cb);
    }

    pub fn get_state(&self, remote_peer_id: &str) -> Option<ConnectionState> {
        let connections = self.connections.lock();
        connections.get(remote_peer_id).map(|c| c.state.clone())
    }

    // =========================================================================
    // Signaling message handler
    // =========================================================================

    /// Start the background task that processes incoming signaling messages.
    fn start_signaling_handler(self: &Arc<Self>, mut rx: mpsc::UnboundedReceiver<SignalingMessage>) {
        let manager = self.clone();
        let handle = tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                manager.handle_signaling_message(msg).await;
            }
            tracing::warn!("Signaling receiver closed, initiating reconnection");
            manager.on_signaling_lost().await;
        });
        *self.signaling_task.lock() = Some(handle);
    }

    /// Dispatch a single signaling message.
    async fn handle_signaling_message(self: &Arc<Self>, msg: SignalingMessage) {
        match msg {
            SignalingMessage::IncomingConnection(payload) => {
                self.handle_incoming_connection(payload).await;
            }
            SignalingMessage::CandidateForward(payload) => {
                self.handle_candidate_forward(payload).await;
            }
            SignalingMessage::AnswerForward(payload) => {
                self.handle_answer_forward(payload).await;
            }
            SignalingMessage::Rejected(payload) => {
                tracing::info!(
                    "Connection rejected by '{}': {}",
                    payload.from_peer_id,
                    payload.reason
                );
                let mut connections = self.connections.lock();
                if let Some(mut conn) = connections.remove(&payload.from_peer_id) {
                    if let Some(h) = conn.punch_task.take() {
                        h.abort();
                    }
                    if let Some(session) = &conn.kcp_session {
                        self.conv_id_index.lock().remove(&session.conv_id());
                    }
                }
                drop(connections);
                self.notify_state(&payload.from_peer_id, ConnectionState::Disconnected);
            }
            SignalingMessage::PeerDisconnected(payload) => {
                tracing::info!("Peer '{}' disconnected", payload.peer_id);
                let mut connections = self.connections.lock();
                if let Some(mut conn) = connections.remove(&payload.peer_id) {
                    if let Some(h) = conn.punch_task.take() {
                        h.abort();
                    }
                    if let Some(session) = &conn.kcp_session {
                        self.conv_id_index.lock().remove(&session.conv_id());
                    }
                }
                drop(connections);
                self.notify_state(&payload.peer_id, ConnectionState::Disconnected);
            }
            SignalingMessage::ReverseConnectForward(payload) => {
                self.handle_reverse_connect_forward(payload).await;
            }
            SignalingMessage::Pong => {
                tracing::trace!("Received Pong from signaling server");
            }
            SignalingMessage::Error(e) => {
                tracing::error!("Signaling server error: [{}] {}", e.code, e.message);
                // If the server says target not found, the remote peer is not
                // reachable via signaling at all. Fail any pending connection
                // directly — reverse connection cannot work either since we
                // cannot reach the peer.
                if e.code == p2p_signaling_proto::error_codes::TARGET_NOT_FOUND {
                    let failed_peers: Vec<String> = {
                        let mut connections = self.connections.lock();
                        let peers: Vec<String> = connections
                            .iter()
                            .filter(|(_, c)| {
                                c.state == ConnectionState::Gathering
                                    || c.state == ConnectionState::Reconnecting
                            })
                            .map(|(pid, _)| pid.clone())
                            .collect();
                        for pid in &peers {
                            if let Some(mut conn) = connections.remove(pid) {
                                if let Some(h) = conn.punch_task.take() {
                                    h.abort();
                                }
                                if let Some(session) = &conn.kcp_session {
                                    self.conv_id_index.lock().remove(&session.conv_id());
                                }
                            }
                        }
                        peers
                    };
                    for pid in &failed_peers {
                        tracing::warn!(
                            "Target peer '{}' not found on signaling server — disconnecting",
                            pid
                        );
                        self.notify_state(pid, ConnectionState::Disconnected);
                    }
                }
            }
            _ => {
                tracing::trace!("Ignoring signaling message: {:?}", msg);
            }
        }
    }

    /// Handle an incoming connection request from a remote peer.
    async fn handle_incoming_connection(self: &Arc<Self>, payload: IncomingConnectionPayload) {
        let from = &payload.from_peer_id;
        tracing::info!(
            "Incoming connection from '{}' (session={})",
            from,
            payload.session_id
        );

        // Check if this is a reconnection from a previously connected peer
        let auto_accept = {
            let rs = self.reconnect_state.lock();
            rs.get(from).map(|s| s.was_connected).unwrap_or(false)
        };

        let accepted = if auto_accept {
            tracing::info!(
                "Auto-accepting reconnection from previously connected peer '{}'",
                from
            );
            // Clean up old connection state before re-establishing
            {
                let mut connections = self.connections.lock();
                if let Some(mut old_conn) = connections.remove(from) {
                    if let Some(h) = old_conn.punch_task.take() {
                        h.abort();
                    }
                    if let Some(h) = old_conn.p2p_retry_task.take() {
                        h.abort();
                    }
                    if let Some(session) = &old_conn.kcp_session {
                        self.conv_id_index.lock().remove(&session.conv_id());
                    }
                }
            }
            true
        } else {
            // Ask the application whether to accept
            let cb = self.incoming_cb.lock();
            if let Some(cb) = cb.as_ref() {
                cb(from)
            } else {
                true
            }
        };

        if !accepted {
            tracing::info!("Rejecting connection from '{}'", from);
            let signaling = self.signaling_tx.lock();
            if let Some(signaling) = signaling.as_ref() {
                let _ = signaling.send(SignalingMessage::Reject(RejectPayload {
                    target_peer_id: from.to_string(),
                    session_id: payload.session_id.clone(),
                    reason: "Rejected by application".to_string(),
                }));
            }
            return;
        }

        // Accept: send Answer
        {
            let signaling = self.signaling_tx.lock();
            if let Some(signaling) = signaling.as_ref() {
                let _ = signaling.send(SignalingMessage::Answer(AnswerPayload {
                    target_peer_id: from.to_string(),
                    session_id: payload.session_id.clone(),
                }));
            }
        }

        let session_hash = punch::compute_session_hash(&payload.session_id);

        // Create peer connection entry (we are the responder)
        {
            let mut connections = self.connections.lock();
            connections.insert(
                from.to_string(),
                PeerConnection {
                    state: ConnectionState::Gathering,
                    session_id: payload.session_id.clone(),
                    session_hash,
                    is_initiator: false,
                    reverse_attempted: false,
                    local_candidates: Vec::new(),
                    remote_candidates: Vec::new(),
                    kcp_session: None,
                    remote_addr: None,
                    probe_tx: None,
                    candidate_tx: None,
                    punch_task: None,
                    answer_received: true,
                    turn_allocation: None,
                    turn_channel: None,
                    punch_timeout_override: None,
                    turn_only: false,
                    p2p_retry_enabled: false,
                    p2p_retry_task: None,
                },
            );
        }

        self.notify_state(from, ConnectionState::Gathering);

        // Send host candidates immediately
        if let Err(e) = self.gather_and_send_candidates(from).await {
            tracing::error!("Failed to gather candidates for '{}': {}", from, e);
            return;
        }

        // Spawn background STUN/TURN gathering — results trickle in asynchronously
        self.spawn_reflexive_gathering(from);

        // Try to start punching (we may already have remote candidates from trickle)
        self.try_start_punching(from).await;

        // Gathering timeout for responder too
        self.spawn_gathering_timeout(from);
    }

    /// Handle a remote candidate forwarded via signaling.
    async fn handle_candidate_forward(self: &Arc<Self>, payload: CandidatePayload) {
        // Find the connection that matches this session_id
        let peer_id = {
            let connections = self.connections.lock();
            connections
                .iter()
                .find(|(_, c)| c.session_id == payload.session_id)
                .map(|(pid, _)| pid.clone())
        };

        let peer_id = match peer_id {
            Some(pid) => pid,
            None => {
                tracing::warn!(
                    "Received candidate for unknown session '{}'",
                    payload.session_id
                );
                return;
            }
        };

        let candidate = match Candidate::from_ice_candidate(&payload.candidate) {
            Some(c) => c,
            None => {
                tracing::warn!(
                    "Failed to parse candidate address: {}",
                    payload.candidate.address
                );
                return;
            }
        };

        tracing::info!(
            "Received remote candidate for '{}': {:?} {} (priority={})",
            peer_id,
            candidate.candidate_type,
            candidate.address,
            candidate.priority
        );

        // Store the candidate and forward to running punch if applicable
        {
            let mut connections = self.connections.lock();
            if let Some(conn) = connections.get_mut(&peer_id) {
                // Limit remote candidates to prevent DoS amplification:
                // a malicious peer could send thousands of fake candidates,
                // each causing probe packets every 25ms.
                const MAX_REMOTE_CANDIDATES: usize = 50;
                if conn.remote_candidates.len() >= MAX_REMOTE_CANDIDATES {
                    tracing::warn!(
                        "Remote candidate limit ({}) reached for '{}', ignoring",
                        MAX_REMOTE_CANDIDATES, peer_id
                    );
                    return;
                }
                // Deduplicate by address
                if conn.remote_candidates.iter().any(|c| c.address == candidate.address) {
                    tracing::trace!("Duplicate remote candidate for '{}': {}", peer_id, candidate.address);
                    return;
                }
                conn.remote_candidates.push(candidate.clone());
                // If punch is already running, send the new candidate dynamically
                if let Some(tx) = &conn.candidate_tx {
                    let _ = tx.send(candidate);
                }
            }
        }

        // Try to start punching if conditions are met
        self.try_start_punching(&peer_id).await;
    }

    /// Handle an answer (accept) from the remote peer.
    async fn handle_answer_forward(self: &Arc<Self>, payload: AnswerPayload) {
        let peer_id = {
            let connections = self.connections.lock();
            connections
                .iter()
                .find(|(_, c)| c.session_id == payload.session_id)
                .map(|(pid, _)| pid.clone())
        };

        let peer_id = match peer_id {
            Some(pid) => pid,
            None => {
                tracing::warn!(
                    "Received answer for unknown session '{}'",
                    payload.session_id
                );
                return;
            }
        };

        tracing::info!("Peer '{}' accepted our connection", peer_id);

        {
            let mut connections = self.connections.lock();
            if let Some(conn) = connections.get_mut(&peer_id) {
                conn.answer_received = true;
            }
        }

        self.try_start_punching(&peer_id).await;
    }

    /// Handle a reverse connection request forwarded from the signaling server.
    ///
    /// The remote peer's punch failed, so they asked us to initiate a fresh
    /// connection in the opposite direction. We clean up the old connection
    /// state and start a brand new connection attempt as the initiator, which
    /// creates fresh NAT mappings that may succeed where the original
    /// direction failed.
    async fn handle_reverse_connect_forward(self: &Arc<Self>, payload: ReverseConnectPayload) {
        let from = &payload.target_peer_id;

        tracing::info!(
            "Reverse connection request from '{}' (session={}) — re-initiating as new initiator",
            from,
            payload.session_id
        );

        // Clean up the existing connection for this peer (abort punch task, etc.)
        {
            let mut connections = self.connections.lock();
            if let Some(mut old_conn) = connections.remove(from) {
                if let Some(h) = old_conn.punch_task.take() {
                    h.abort();
                }
                if let Some(session) = &old_conn.kcp_session {
                    self.conv_id_index.lock().remove(&session.conv_id());
                }
                // Drop probe_tx / candidate_tx so the old punch engine stops
            }
        }

        // Generate a fresh session for the reverse attempt
        let session_id = uuid::Uuid::new_v4().to_string();
        let session_hash = punch::compute_session_hash(&session_id);

        // Send a connect request to the remote peer (we are now the initiator)
        {
            let signaling = self.signaling_tx.lock();
            if let Some(signaling) = signaling.as_ref() {
                let _ = signaling.send(SignalingMessage::ConnectRequest(ConnectRequestPayload {
                    target_peer_id: from.to_string(),
                    session_id: session_id.clone(),
                }));
            }
        }

        // Create a new peer connection entry — we are the initiator now,
        // and mark reverse_attempted = true to prevent infinite loops.
        {
            let mut connections = self.connections.lock();
            connections.insert(
                from.to_string(),
                PeerConnection {
                    state: ConnectionState::Gathering,
                    session_id: session_id.clone(),
                    session_hash,
                    is_initiator: true,
                    reverse_attempted: true,
                    local_candidates: Vec::new(),
                    remote_candidates: Vec::new(),
                    kcp_session: None,
                    remote_addr: None,
                    probe_tx: None,
                    candidate_tx: None,
                    punch_task: None,
                    answer_received: false,
                    turn_allocation: None,
                    turn_channel: None,
                    punch_timeout_override: None,
                    turn_only: false,
                    p2p_retry_enabled: false,
                    p2p_retry_task: None,
                },
            );
        }

        self.notify_state(from, ConnectionState::Gathering);

        // Gather and send host candidates
        if let Err(e) = self.gather_and_send_candidates(from).await {
            tracing::error!("Failed to gather candidates for reverse '{}': {}", from, e);
            return;
        }

        // Spawn background STUN/TURN gathering
        self.spawn_reflexive_gathering(from);

        // Try to start punching
        self.try_start_punching(from).await;

        // Ensure the reverse connection attempt has a timeout — without this,
        // the connection could be stuck in Gathering forever if the remote
        // peer never responds.
        self.spawn_gathering_timeout(from);
    }

    // =========================================================================
    // Candidate gathering
    // =========================================================================

    /// Gather host (local network) candidates and send them immediately via signaling.
    ///
    /// STUN server-reflexive and TURN relay candidates are gathered asynchronously
    /// in background tasks via `spawn_reflexive_gathering()` and trickled in as
    /// they become available. This avoids blocking hole punching on slow STUN servers.
    async fn gather_and_send_candidates(&self, remote_peer_id: &str) -> Result<(), P2pError> {
        // Host candidates (local network addresses) — instant, no I/O
        let v4_port = self.socket.v4_port();
        let v6_port = self.socket.v6_port();
        let mut candidates = gather_host_candidates(v4_port);
        // If IPv6 port differs, correct it
        if v6_port != 0 && v6_port != v4_port {
            for c in &mut candidates {
                if c.address.is_ipv6() {
                    c.address.set_port(v6_port);
                }
            }
        }

        // Deduplicate candidates by address
        let mut seen = std::collections::HashSet::new();
        candidates.retain(|c| seen.insert(c.address));

        tracing::info!(
            "Sending {} host candidates for '{}' (STUN/TURN will trickle):",
            candidates.len(),
            remote_peer_id
        );
        for c in &candidates {
            tracing::info!(
                "  {:?} {} (priority={})",
                c.candidate_type,
                c.address,
                c.priority
            );
        }

        // Store local candidates
        let session_id = {
            let mut connections = self.connections.lock();
            if let Some(conn) = connections.get_mut(remote_peer_id) {
                conn.local_candidates = candidates.clone();
                conn.session_id.clone()
            } else {
                return Ok(());
            }
        };

        // Send candidates via signaling
        let signaling = self.signaling_tx.lock();
        if let Some(signaling) = signaling.as_ref() {
            for candidate in &candidates {
                let _ = signaling.send(SignalingMessage::Candidate(CandidatePayload {
                    target_peer_id: remote_peer_id.to_string(),
                    session_id: session_id.clone(),
                    candidate: candidate.to_ice_candidate(),
                }));
            }
        }

        Ok(())
    }

    /// Trickle a locally-discovered candidate (STUN/TURN) to the remote peer.
    ///
    /// Called from background STUN/TURN tasks as results arrive. Stores the
    /// candidate, sends it via signaling, and tries to start punching if
    /// conditions are now met.
    ///
    /// In `turn_only` mode, when a relay candidate arrives the connection
    /// bypasses hole punching and goes straight to TURN relay.
    async fn trickle_local_candidate(self: &Arc<Self>, peer_id: &str, candidate: Candidate) {
        // 1. Store the candidate (with dedup) and check turn_only status
        let (session_id, is_turn_only, is_relay_candidate) = {
            let mut connections = self.connections.lock();
            if let Some(conn) = connections.get_mut(peer_id) {
                if conn.local_candidates.iter().any(|c| c.address == candidate.address) {
                    return;
                }
                let is_relay = candidate.candidate_type == p2p_signaling_proto::CandidateType::Relay;
                conn.local_candidates.push(candidate.clone());
                (conn.session_id.clone(), conn.turn_only, is_relay)
            } else {
                return;
            }
        };

        // 2. Send to remote peer via signaling
        {
            let signaling = self.signaling_tx.lock();
            if let Some(signaling) = signaling.as_ref() {
                let _ = signaling.send(SignalingMessage::Candidate(CandidatePayload {
                    target_peer_id: peer_id.to_string(),
                    session_id,
                    candidate: candidate.to_ice_candidate(),
                }));
            }
        }

        tracing::info!(
            "Trickled local candidate {:?} {} to '{}'",
            candidate.candidate_type, candidate.address, peer_id
        );

        // 3. In turn_only mode, trigger direct TURN relay when relay candidate arrives
        if is_turn_only && is_relay_candidate {
            tracing::info!(
                "turn_only mode: TURN allocation ready for '{}', establishing relay directly",
                peer_id
            );
            self.try_direct_turn_relay(peer_id).await;
            return;
        }

        // 4. Try to start punching (if not already started and conditions now met)
        self.try_start_punching(peer_id).await;
    }

    /// Spawn background tasks to gather server-reflexive (STUN) and relay (TURN) candidates.
    ///
    /// Each STUN server query (IPv4 and IPv6 separately) runs as an independent task.
    /// Results are trickled to the remote peer via signaling as they arrive, without
    /// blocking hole punching on slower queries.
    ///
    /// C6: These fire-and-forget tasks use `Weak<Self>` instead of `Arc<Self>` to
    /// avoid preventing the manager from being dropped. If the manager is shut down
    /// before a STUN query completes, the Weak reference expires and the task exits.
    fn spawn_reflexive_gathering(self: &Arc<Self>, peer_id: &str) {
        let stun_timeout = self.config.stun_timeout;

        tracing::info!(
            "STUN gathering: {} servers | timeout={:?} | IPv4={} IPv6={}",
            self.config.stun_servers.len(),
            stun_timeout,
            self.socket.v4_socket().is_some(),
            self.socket.v6_socket().is_some(),
        );
        for (i, s) in self.config.stun_servers.iter().enumerate() {
            tracing::info!("  STUN [{}]: {}", i + 1, s);
        }

        for server_str in &self.config.stun_servers {
            // IPv4 STUN task
            if self.socket.v4_socket().is_some() {
                let manager_weak = Arc::downgrade(self);
                let peer_id = peer_id.to_string();
                let server = server_str.clone();
                let socket = self.socket.clone();
                let router = self.stun_router.clone();
                tokio::spawn(async move {
                    let stun_client = StunClient::new(stun_timeout);
                    let addrs = match p2p_stun::StunServerList::resolve(&server).await {
                        Ok(a) => a,
                        Err(e) => {
                            tracing::warn!("STUN DNS resolve failed for {}: {}", server, e);
                            return;
                        }
                    };
                    for server_addr in addrs {
                        if let SocketAddr::V4(_) = server_addr {
                            if let Some(udp_socket) = socket.v4_socket() {
                                match stun_client.binding_request_routed(
                                    udp_socket, server_addr, &router,
                                ).await {
                                    Ok(mapped_addr) => {
                                        tracing::info!(
                                            "STUN trickle: srflx {} (from {})",
                                            mapped_addr, server
                                        );
                                        if let Some(manager) = manager_weak.upgrade() {
                                            manager.trickle_local_candidate(
                                                &peer_id,
                                                Candidate::server_reflexive(mapped_addr),
                                            ).await;
                                        }
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            "STUN binding to {} (v4) failed: {}",
                                            server_addr, e
                                        );
                                    }
                                }
                            }
                            return;
                        }
                    }
                });
            }

            // IPv6 STUN task
            if self.socket.v6_socket().is_some() {
                let manager_weak = Arc::downgrade(self);
                let peer_id = peer_id.to_string();
                let server = server_str.clone();
                let socket = self.socket.clone();
                let router = self.stun_router.clone();
                tokio::spawn(async move {
                    let stun_client = StunClient::new(stun_timeout);
                    let addrs = match p2p_stun::StunServerList::resolve(&server).await {
                        Ok(a) => a,
                        Err(e) => {
                            tracing::warn!("STUN DNS resolve failed for {}: {}", server, e);
                            return;
                        }
                    };
                    for server_addr in addrs {
                        if let SocketAddr::V6(_) = server_addr {
                            if let Some(udp_socket) = socket.v6_socket() {
                                match stun_client.binding_request_routed(
                                    udp_socket, server_addr, &router,
                                ).await {
                                    Ok(mapped_addr) => {
                                        tracing::info!(
                                            "STUN trickle: srflx {} (from {})",
                                            mapped_addr, server
                                        );
                                        if let Some(manager) = manager_weak.upgrade() {
                                            manager.trickle_local_candidate(
                                                &peer_id,
                                                Candidate::server_reflexive(mapped_addr),
                                            ).await;
                                        }
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            "STUN binding to {} (v6) failed: {}",
                                            server_addr, e
                                        );
                                    }
                                }
                            }
                            return;
                        }
                    }
                });
            }
        }

        // TURN allocation task (if configured)
        if let Some(turn_config) = self.turn_config.read().clone() {
            let manager_weak = Arc::downgrade(self);
            let peer_id = peer_id.to_string();
            tokio::spawn(async move {
                let manager = match manager_weak.upgrade() {
                    Some(m) => m,
                    None => return,
                };
                match manager.allocate_turn_relay(&turn_config, &peer_id).await {
                    Ok(relay_addr) => {
                        tracing::info!("TURN trickle: relay {}", relay_addr);
                        manager.trickle_local_candidate(
                            &peer_id,
                            Candidate::relay(relay_addr),
                        ).await;
                    }
                    Err(e) => {
                        tracing::warn!("TURN allocation failed: {}", e);
                    }
                }
            });
        }
    }

    /// Allocate a TURN relay address using the StunResponseRouter for response routing.
    ///
    /// Implements the two-step TURN long-term credential auth flow (RFC 5766):
    /// 1. Send unauthenticated Allocate → server responds with 401 + REALM + NONCE
    /// 2. Send authenticated Allocate with USERNAME/REALM/NONCE/MESSAGE-INTEGRITY
    async fn allocate_turn_relay(
        &self,
        turn_config: &crate::config::TurnConfig,
        remote_peer_id: &str,
    ) -> Result<SocketAddr, P2pError> {
        let server_addr: SocketAddr = turn_config
            .server_addr
            .parse()
            .map_err(|_| P2pError::InvalidConfig("Invalid TURN server address".into()))?;

        let mut credentials = TurnCredentials::new(
            turn_config.username.clone(),
            turn_config.password.clone(),
        );

        // H15: Select socket based on TURN server address family
        let udp_socket = match server_addr {
            SocketAddr::V4(_) => self.socket.v4_socket()
                .ok_or(P2pError::NotConnected)?,
            SocketAddr::V6(_) => self.socket.v6_socket()
                .ok_or_else(|| P2pError::InvalidConfig(
                    "IPv6 TURN server but no IPv6 socket available".into(),
                ))?,
        };

        let timeout = self.config.stun_timeout;

        // Step 1: Send unauthenticated Allocate request.
        // Per RFC 5766 Section 6, the server will respond with 401 Unauthorized
        // containing REALM and NONCE attributes needed for authentication.
        let txn_id1 = p2p_turn::TurnAllocation::generate_transaction_id();
        let request1 = p2p_turn::TurnAllocation::build_allocate_request(&txn_id1, &credentials);
        let rx1 = self.stun_router.expect_response(txn_id1);

        udp_socket.send_to(&request1, server_addr).await?;

        let data1 = match tokio::time::timeout(timeout, rx1).await {
            Ok(Ok(data)) => data,
            Ok(Err(_)) => {
                self.stun_router.cancel(&txn_id1);
                return Err(P2pError::Turn(p2p_turn::TurnError::Timeout));
            }
            Err(_) => {
                self.stun_router.cancel(&txn_id1);
                return Err(P2pError::Turn(p2p_turn::TurnError::Timeout));
            }
        };

        // Check if the response is an error (expected: 401 Unauthorized)
        let final_data = if p2p_turn::TurnAllocation::is_error_response(&data1) {
            // Parse the 401 to extract REALM and NONCE
            let challenge = p2p_turn::TurnAllocation::parse_error_response(&data1, &txn_id1)?;

            if challenge.error_code != 401 {
                return Err(P2pError::Turn(p2p_turn::TurnError::AllocationFailed(
                    format!("TURN server returned error {}", challenge.error_code),
                )));
            }

            if challenge.realm.is_empty() || challenge.nonce.is_empty() {
                return Err(P2pError::Turn(p2p_turn::TurnError::AuthFailed));
            }

            tracing::debug!(
                "TURN 401 challenge: realm='{}', nonce='{}'",
                challenge.realm, challenge.nonce
            );

            // Update credentials with realm and nonce from the challenge
            credentials.update_auth(challenge.realm, challenge.nonce);

            // Step 2: Send authenticated Allocate request with MESSAGE-INTEGRITY
            let txn_id2 = p2p_turn::TurnAllocation::generate_transaction_id();
            let request2 = p2p_turn::TurnAllocation::build_authenticated_allocate_request(
                &txn_id2, &credentials,
            )?;
            let rx2 = self.stun_router.expect_response(txn_id2);

            udp_socket.send_to(&request2, server_addr).await?;

            match tokio::time::timeout(timeout, rx2).await {
                Ok(Ok(data)) => {
                    // Check if the authenticated request also returned an error
                    if p2p_turn::TurnAllocation::is_error_response(&data) {
                        let err = p2p_turn::TurnAllocation::parse_error_response(&data, &txn_id2)?;
                        self.stun_router.cancel(&txn_id2);
                        return Err(P2pError::Turn(p2p_turn::TurnError::AllocationFailed(
                            format!("TURN auth failed with error {}", err.error_code),
                        )));
                    }
                    (data, txn_id2)
                }
                Ok(Err(_)) | Err(_) => {
                    self.stun_router.cancel(&txn_id2);
                    return Err(P2pError::Turn(p2p_turn::TurnError::Timeout));
                }
            }
        } else {
            // Server accepted unauthenticated request (rare, but possible for local TURN)
            (data1, txn_id1)
        };

        // Parse the successful Allocate response
        let (relayed_addr, mapped_addr, lifetime) =
            p2p_turn::TurnAllocation::parse_allocate_response(&final_data.0, &final_data.1)?;

        let allocation = p2p_turn::TurnAllocation::from_parts(
            server_addr,
            relayed_addr,
            mapped_addr,
            lifetime,
            credentials,
        );

        tracing::info!(
            "TURN allocation: relay={}, mapped={}, lifetime={}s",
            relayed_addr, mapped_addr, lifetime
        );

        // Store the allocation
        {
            let mut connections = self.connections.lock();
            if let Some(conn) = connections.get_mut(remote_peer_id) {
                conn.turn_allocation = Some(allocation);
            }
        }

        Ok(relayed_addr)
    }

    // =========================================================================
    // Hole punching
    // =========================================================================

    /// Spawn a watchdog that fails the connection if it's still in Gathering
    /// after 10 seconds. This handles cases where the remote peer is
    /// unreachable (e.g., not registered) and we never receive an Answer or
    /// remote candidates.
    ///
    /// C6: Uses `Weak<Self>` to avoid preventing the manager from being dropped.
    fn spawn_gathering_timeout(self: &Arc<Self>, peer_id: &str) {
        let manager_weak = Arc::downgrade(self);
        let peer_id = peer_id.to_string();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(10)).await;
            let manager = match manager_weak.upgrade() {
                Some(m) => m,
                None => return, // manager already shut down
            };
            let should_fail = {
                let connections = manager.connections.lock();
                connections
                    .get(&peer_id)
                    .is_some_and(|c| c.state == ConnectionState::Gathering)
            };
            if should_fail {
                tracing::warn!(
                    "Gathering timeout for '{}' — no answer/candidates received in 10s",
                    peer_id
                );
                // Remove the connection directly; the peer is unreachable so
                // reverse connection would not help.
                {
                    let mut connections = manager.connections.lock();
                    if let Some(mut conn) = connections.remove(&peer_id) {
                        if let Some(h) = conn.punch_task.take() {
                            h.abort();
                        }
                        if let Some(session) = &conn.kcp_session {
                            manager.conv_id_index.lock().remove(&session.conv_id());
                        }
                    }
                }
                manager.notify_state(&peer_id, ConnectionState::Disconnected);
            }
        });
    }

    /// Check if conditions are met to start hole punching, and if so, start it.
    ///
    /// Starts almost immediately (50ms batching delay). Late-arriving candidates
    /// are forwarded dynamically to the running punch engine via `candidate_tx`.
    async fn try_start_punching(self: &Arc<Self>, peer_id: &str) {
        // Atomic check-and-transition to prevent concurrent callers from
        // both starting punch (possible with trickle candidates arriving
        // from multiple background STUN tasks).
        let (should_start, punch_timeout) = {
            let mut connections = self.connections.lock();
            if let Some(conn) = connections.get_mut(peer_id) {
                // Skip punching entirely in turn_only mode
                if conn.turn_only {
                    return;
                }
                if conn.state == ConnectionState::Gathering
                    && !conn.local_candidates.is_empty()
                    && !conn.remote_candidates.is_empty()
                    && conn.answer_received
                    && conn.punch_task.is_none()
                {
                    conn.state = ConnectionState::Punching;
                    let timeout = conn.punch_timeout_override
                        .unwrap_or(self.config.punch_timeout);
                    (true, timeout)
                } else {
                    (false, Duration::ZERO)
                }
            } else {
                (false, Duration::ZERO)
            }
        };

        if !should_start {
            return;
        }

        self.notify_state(peer_id, ConnectionState::Punching);

        // Brief pause to batch candidates that arrive together.
        // We keep this very short because late candidates are forwarded
        // dynamically to the running punch engine via candidate_tx.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Now collect ALL candidates (including those that arrived during the wait)
        let (remote_candidates, session_id) = {
            let connections = self.connections.lock();
            match connections.get(peer_id) {
                Some(conn) => (conn.remote_candidates.clone(), conn.session_id.clone()),
                None => return,
            }
        };

        // Create channels for this connection:
        // - probe channel: feeds received UDP probe packets to punch engine
        // - candidate channel: feeds late-arriving remote candidates to punch engine
        let (probe_tx, probe_rx) = mpsc::unbounded_channel();
        let (candidate_tx, candidate_rx) = mpsc::unbounded_channel();
        {
            let mut connections = self.connections.lock();
            if let Some(conn) = connections.get_mut(peer_id) {
                conn.probe_tx = Some(probe_tx);
                conn.candidate_tx = Some(candidate_tx);
            }
        }

        // Spawn the punch task
        let manager = self.clone();
        let peer_id_owned = peer_id.to_string();
        let socket = self.socket.clone();
        let timeout = punch_timeout;

        let handle = tokio::spawn(async move {
            tracing::info!("Starting hole punch for '{}'...", peer_id_owned);

            let result = punch::run_hole_punch(
                socket,
                remote_candidates,
                &session_id,
                timeout,
                probe_rx,
                candidate_rx,
            )
            .await;

            match result {
                Ok(punch_result) => {
                    tracing::info!(
                        "Hole punch succeeded for '{}': remote_addr={}",
                        peer_id_owned,
                        punch_result.remote_addr
                    );
                    manager
                        .on_punch_success(&peer_id_owned, &session_id, punch_result.remote_addr)
                        .await;
                }
                Err(e) => {
                    tracing::warn!("Hole punch failed for '{}': {}", peer_id_owned, e);
                    manager.on_punch_failed(&peer_id_owned).await;
                }
            }
        });

        {
            let mut connections = self.connections.lock();
            if let Some(conn) = connections.get_mut(peer_id) {
                conn.punch_task = Some(handle);
            }
        }
    }

    /// Establish a KCP session directly over TURN relay, skipping hole punching.
    ///
    /// Used in `turn_only` mode: when the TURN allocation completes, this method
    /// creates the KCP session routed through the relay without attempting any
    /// UDP probes. Reuses the same relay setup logic as `on_punch_failed()`.
    async fn try_direct_turn_relay(self: &Arc<Self>, peer_id: &str) {
        let turn_info = {
            let connections = self.connections.lock();
            if let Some(conn) = connections.get(peer_id) {
                // Only proceed if we're still in Gathering (not already connected/relayed)
                if conn.state != ConnectionState::Gathering {
                    return;
                }
                conn.turn_allocation.as_ref().map(|alloc| {
                    (alloc.server_addr, alloc.relayed_addr, conn.session_id.clone())
                })
            } else {
                None
            }
        };

        let (turn_server, relay_addr, session_id) = match turn_info {
            Some(info) => info,
            None => {
                tracing::warn!(
                    "turn_only mode but no TURN allocation for '{}' — waiting",
                    peer_id
                );
                return;
            }
        };

        tracing::info!(
            "Direct TURN relay for '{}': relay={}, server={}",
            peer_id, relay_addr, turn_server
        );

        let conv_id = punch::derive_conv_id(&session_id);

        // Assign a channel number for this peer
        let channel = {
            let mut connections = self.connections.lock();
            let next = connections.values()
                .filter_map(|c| c.turn_channel)
                .max()
                .unwrap_or(0x3FFF) + 1;
            if next > 0x7FFF {
                tracing::error!(
                    "TURN channel number overflow for '{}': 0x{:04X} > 0x7FFF",
                    peer_id, next
                );
                if let Some(mut conn) = connections.remove(peer_id) {
                    if let Some(h) = conn.punch_task.take() {
                        h.abort();
                    }
                    if let Some(session) = &conn.kcp_session {
                        self.conv_id_index.lock().remove(&session.conv_id());
                    }
                }
                drop(connections);
                self.notify_state(peer_id, ConnectionState::Disconnected);
                return;
            }
            if let Some(conn) = connections.get_mut(peer_id) {
                conn.turn_channel = Some(next);
            }
            next
        };

        // Create KCP session and enable TURN relay wrapping
        let session = KcpSession::new(
            conv_id,
            turn_server,
            self.socket.clone(),
            self.config.kcp_mode,
        );
        session.enable_turn_relay(channel, turn_server);
        session.stats.is_relayed.store(true, std::sync::atomic::Ordering::Relaxed);

        {
            let mut connections = self.connections.lock();
            if let Some(conn) = connections.get_mut(peer_id) {
                conn.kcp_session = Some(Arc::new(session));
                conn.remote_addr = Some(turn_server);
                conn.state = ConnectionState::Relayed;
                conn.probe_tx = None;
                conn.candidate_tx = None;
                conn.punch_task = None;

                // Auto-start P2P retry loop if flag was pre-set
                if conn.p2p_retry_enabled && conn.p2p_retry_task.is_none() {
                    let manager_weak = Arc::downgrade(self);
                    let pid = peer_id.to_string();
                    conn.p2p_retry_task = Some(tokio::spawn(async move {
                        Self::run_p2p_retry_loop(manager_weak, pid).await;
                    }));
                }
            }
            self.conv_id_index.lock().insert(conv_id, peer_id.to_string());
        }

        // Reset reconnection state on successful relay
        {
            let mut rs = self.reconnect_state.lock();
            if let Some(state) = rs.get_mut(peer_id) {
                state.attempts = 0;
                state.was_connected = true;
            } else {
                rs.insert(peer_id.to_string(), ReconnectState {
                    attempts: 0,
                    was_connected: true,
                });
            }
        }

        self.notify_state(peer_id, ConnectionState::Relayed);
    }

    /// Called when hole punching succeeds. Creates the KCP session.
    async fn on_punch_success(
        self: &Arc<Self>,
        peer_id: &str,
        session_id: &str,
        remote_addr: SocketAddr,
    ) {
        let conv_id = punch::derive_conv_id(session_id);
        tracing::info!(
            "Establishing KCP session for '{}': conv_id={}, remote={}",
            peer_id,
            conv_id,
            remote_addr
        );

        let session = KcpSession::new(
            conv_id,
            remote_addr,
            self.socket.clone(),
            self.config.kcp_mode,
        );

        {
            let mut connections = self.connections.lock();
            if let Some(conn) = connections.get_mut(peer_id) {
                conn.kcp_session = Some(Arc::new(session));
                conn.remote_addr = Some(remote_addr);
                conn.state = ConnectionState::Connected;
                conn.probe_tx = None;
                conn.candidate_tx = None;
                conn.punch_task = None;
            }
            // M4: Register conv_id → peer_id mapping for fast packet routing
            self.conv_id_index.lock().insert(conv_id, peer_id.to_string());
        }

        // Reset reconnection state on successful connection
        {
            let mut rs = self.reconnect_state.lock();
            if let Some(state) = rs.get_mut(peer_id) {
                state.attempts = 0;
                state.was_connected = true;
            } else {
                rs.insert(peer_id.to_string(), ReconnectState {
                    attempts: 0,
                    was_connected: true,
                });
            }
        }

        self.notify_state(peer_id, ConnectionState::Connected);
    }

    /// Called when hole punching fails. Attempts TURN relay fallback.
    ///
    /// If a TURN allocation exists, creates a KCP session that routes through
    /// the TURN relay using ChannelData. This guarantees connectivity even when
    /// both peers are behind symmetric NATs.
    async fn on_punch_failed(self: &Arc<Self>, peer_id: &str) {
        // Check if we have a TURN allocation for relay fallback
        let turn_info = {
            let connections = self.connections.lock();
            if let Some(conn) = connections.get(peer_id) {
                conn.turn_allocation.as_ref().map(|alloc| {
                    (alloc.server_addr, alloc.relayed_addr, conn.session_id.clone())
                })
            } else {
                None
            }
        };

        if let Some((turn_server, relay_addr, session_id)) = turn_info {
            tracing::info!(
                "Falling back to TURN relay for '{}': relay={}, server={}",
                peer_id, relay_addr, turn_server
            );

            let conv_id = punch::derive_conv_id(&session_id);

            // Assign a channel number for this peer (starting from 0x4000)
            // M5: Validate channel is within TURN ChannelData range (0x4000-0x7FFF)
            let channel = {
                let mut connections = self.connections.lock();
                let next = connections.values()
                    .filter_map(|c| c.turn_channel)
                    .max()
                    .unwrap_or(0x3FFF) + 1;
                if next > 0x7FFF {
                    tracing::error!(
                        "TURN channel number overflow for '{}': 0x{:04X} > 0x7FFF",
                        peer_id, next
                    );
                    // Fall through to disconnect below
                    {
                        if let Some(mut conn) = connections.remove(peer_id) {
                            if let Some(h) = conn.punch_task.take() {
                                h.abort();
                            }
                            if let Some(session) = &conn.kcp_session {
                                self.conv_id_index.lock().remove(&session.conv_id());
                            }
                        }
                    }
                    drop(connections);
                    self.notify_state(peer_id, ConnectionState::Disconnected);
                    return;
                }
                if let Some(conn) = connections.get_mut(peer_id) {
                    conn.turn_channel = Some(next);
                }
                next
            };

            // Create KCP session and enable TURN relay wrapping
            let session = KcpSession::new(
                conv_id,
                turn_server,
                self.socket.clone(),
                self.config.kcp_mode,
            );
            session.enable_turn_relay(channel, turn_server);
            session.stats.is_relayed.store(true, std::sync::atomic::Ordering::Relaxed);

            {
                let mut connections = self.connections.lock();
                if let Some(conn) = connections.get_mut(peer_id) {
                    conn.kcp_session = Some(Arc::new(session));
                    conn.remote_addr = Some(turn_server);
                    conn.state = ConnectionState::Relayed;
                    conn.probe_tx = None;
                    conn.candidate_tx = None;
                    conn.punch_task = None;

                    // Auto-start P2P retry loop if flag was pre-set
                    if conn.p2p_retry_enabled && conn.p2p_retry_task.is_none() {
                        let manager_weak = Arc::downgrade(self);
                        let pid = peer_id.to_string();
                        conn.p2p_retry_task = Some(tokio::spawn(async move {
                            Self::run_p2p_retry_loop(manager_weak, pid).await;
                        }));
                    }
                }
                // M4: Register conv_id → peer_id mapping for fast packet routing
                self.conv_id_index.lock().insert(conv_id, peer_id.to_string());
            }

            // Reset reconnection state on successful relay
            {
                let mut rs = self.reconnect_state.lock();
                if let Some(state) = rs.get_mut(peer_id) {
                    state.attempts = 0;
                    state.was_connected = true;
                } else {
                    rs.insert(peer_id.to_string(), ReconnectState {
                        attempts: 0,
                        was_connected: true,
                    });
                }
            }

            self.notify_state(peer_id, ConnectionState::Relayed);
        } else {
            // No TURN fallback — try reverse connection before giving up.
            // If we are the initiator and haven't tried reverse yet, ask the
            // remote peer to initiate a connection back to us. The remote
            // peer's NAT mapping may be more favourable in the reverse
            // direction.
            let try_reverse = {
                let connections = self.connections.lock();
                if let Some(conn) = connections.get(peer_id) {
                    conn.is_initiator && !conn.reverse_attempted
                } else {
                    false
                }
            };

            if try_reverse {
                let session_id = {
                    let mut connections = self.connections.lock();
                    if let Some(conn) = connections.get_mut(peer_id) {
                        conn.reverse_attempted = true;
                        conn.state = ConnectionState::Reconnecting;
                        conn.probe_tx = None;
                        conn.candidate_tx = None;
                        conn.punch_task = None;
                        conn.session_id.clone()
                    } else {
                        return;
                    }
                };

                tracing::info!(
                    "Punch failed for '{}' — requesting reverse connection (session={})",
                    peer_id, session_id
                );
                self.notify_state(peer_id, ConnectionState::Reconnecting);

                let signaling = self.signaling_tx.lock();
                if let Some(signaling) = signaling.as_ref() {
                    let _ = signaling.send(SignalingMessage::ReverseConnect(
                        ReverseConnectPayload {
                            target_peer_id: peer_id.to_string(),
                            session_id,
                        },
                    ));
                }

                // Ensure the reverse connection attempt has a timeout — without
                // this, the connection could be stuck in Reconnecting forever.
                self.spawn_gathering_timeout(peer_id);
            } else {
                // Already tried reverse or we are the responder — give up
                tracing::error!(
                    "Hole punch failed for '{}' and no TURN relay available",
                    peer_id
                );

                {
                    let mut connections = self.connections.lock();
                    if let Some(mut conn) = connections.remove(peer_id) {
                        conn.probe_tx = None;
                        conn.candidate_tx = None;
                        if let Some(h) = conn.punch_task.take() {
                            h.abort();
                        }
                        if let Some(session) = &conn.kcp_session {
                            self.conv_id_index.lock().remove(&session.conv_id());
                        }
                    }
                }
                self.notify_state(peer_id, ConnectionState::Disconnected);
            }
        }
    }

    // =========================================================================
    // UDP receive loop
    // =========================================================================

    fn start_recv_loop(self: &Arc<Self>) {
        let manager = self.clone();
        let handle = tokio::spawn(async move {
            let mut buf = [0u8; 65535];
            let mut recv_count: u64 = 0;
            loop {
                match manager.socket.recv_from(&mut buf).await {
                    Ok((len, from_addr)) => {
                        recv_count += 1;
                        let data = &buf[..len];
                        match classify_packet(data) {
                            PacketType::Stun => {
                                if !manager.stun_router.try_route(data) {
                                    tracing::trace!(
                                        "Unmatched STUN packet from {} ({} bytes)",
                                        from_addr, len
                                    );
                                }
                            }
                            PacketType::PunchProbe => {
                                manager.handle_punch_probe(data, from_addr);
                            }
                            PacketType::Kcp { conv_id } => {
                                if recv_count <= 10 || recv_count % 200 == 0 {
                                    tracing::debug!(
                                        "RecvLoop: #{} KCP packet from {} ({} bytes, conv_id={}, wire[0..2]={:02x},{:02x})",
                                        recv_count, from_addr, len, conv_id,
                                        data.get(0).copied().unwrap_or(0),
                                        data.get(1).copied().unwrap_or(0),
                                    );
                                }
                                manager.handle_kcp_packet(data, from_addr, conv_id);
                            }
                            PacketType::KcpOpaque => {
                                if recv_count <= 10 || recv_count % 200 == 0 {
                                    tracing::debug!(
                                        "RecvLoop: #{} KcpOpaque packet from {} ({} bytes, wire[0..2]={:02x},{:02x})",
                                        recv_count, from_addr, len,
                                        data.get(0).copied().unwrap_or(0),
                                        data.get(1).copied().unwrap_or(0),
                                    );
                                }
                                manager.handle_kcp_opaque(data, from_addr);
                            }
                            PacketType::TurnChannelData { channel } => {
                                manager.handle_turn_channel_data(data, channel);
                            }
                            PacketType::Unknown => {
                                tracing::trace!(
                                    "Unknown packet from {} ({} bytes)",
                                    from_addr,
                                    len
                                );
                            }
                        }
                    }
                    Err(e) => {
                        // M13: Use cross-platform error matching instead of
                        // Windows-specific raw error code 10054 (WSAECONNRESET).
                        let is_connreset = matches!(&e, P2pError::Io(io_err)
                            if io_err.kind() == std::io::ErrorKind::ConnectionReset
                            || io_err.raw_os_error() == Some(10054));
                        if !is_connreset {
                            tracing::error!("UDP recv error: {}", e);
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                    }
                }
            }
        });
        *self.recv_task.lock() = Some(handle);
    }

    // =========================================================================
    // Feature control APIs
    // =========================================================================

    pub fn get_stats(&self, remote_peer_id: &str) -> Result<StatsSnapshot, P2pError> {
        let connections = self.connections.lock();
        let conn = connections
            .get(remote_peer_id)
            .ok_or_else(|| P2pError::PeerNotFound(remote_peer_id.to_string()))?;
        let session = conn.kcp_session.as_ref().ok_or(P2pError::NotConnected)?;
        let mut snap = session.stats.snapshot();
        // Fill in connection-level info not tracked in atomic stats
        if let Some(addr) = conn.remote_addr {
            snap.remote_addr = addr.to_string();
        }
        snap.local_port = self.socket.v4_port();
        Ok(snap)
    }

    /// Enable or disable automatic P2P retry for a peer currently in Relayed state.
    ///
    /// When enabled, a background task periodically attempts hole punching (every 5s
    /// with a 3s timeout). If punching succeeds, the session seamlessly switches from
    /// TURN relay to direct P2P (`switch_remote()` + `disable_turn_relay()`).
    ///
    /// This is a per-peer dynamic toggle, similar to `enable_fec()`.
    pub fn enable_p2p_retry(
        self: &Arc<Self>,
        remote_peer_id: &str,
        enabled: bool,
    ) -> Result<(), P2pError> {
        let mut connections = self.connections.lock();
        let conn = connections
            .get_mut(remote_peer_id)
            .ok_or_else(|| P2pError::PeerNotFound(remote_peer_id.to_string()))?;

        conn.p2p_retry_enabled = enabled;

        if enabled {
            // Only spawn retry loop if currently relayed and no retry task running
            if conn.state == ConnectionState::Relayed && conn.p2p_retry_task.is_none() {
                let manager_weak = Arc::downgrade(self);
                let peer_id = remote_peer_id.to_string();
                let handle = tokio::spawn(async move {
                    Self::run_p2p_retry_loop(manager_weak, peer_id).await;
                });
                conn.p2p_retry_task = Some(handle);
                tracing::info!("P2P retry enabled for '{}'", remote_peer_id);
            } else {
                tracing::info!(
                    "P2P retry flag set for '{}' (will activate when Relayed)",
                    remote_peer_id
                );
            }
        } else {
            // Abort existing retry task
            if let Some(h) = conn.p2p_retry_task.take() {
                h.abort();
                tracing::info!("P2P retry disabled for '{}'", remote_peer_id);
            }
        }

        Ok(())
    }

    /// Background loop that periodically attempts P2P hole punching while in Relayed state.
    ///
    /// Uses `Weak<ConnectionManager>` to avoid preventing shutdown. Exits if:
    /// - The manager is dropped
    /// - The peer is disconnected
    /// - The connection is no longer in Relayed state
    /// - `p2p_retry_enabled` is cleared
    async fn run_p2p_retry_loop(manager_weak: std::sync::Weak<ConnectionManager>, peer_id: String) {
        loop {
            // Wait 5 seconds between retry attempts
            tokio::time::sleep(Duration::from_secs(5)).await;

            let manager = match manager_weak.upgrade() {
                Some(m) => m,
                None => {
                    tracing::debug!("P2P retry loop for '{}': manager dropped, exiting", peer_id);
                    return;
                }
            };

            // Check if we should still be retrying
            let (should_retry, remote_candidates, session_id) = {
                let connections = manager.connections.lock();
                if let Some(conn) = connections.get(&peer_id) {
                    if conn.state != ConnectionState::Relayed || !conn.p2p_retry_enabled {
                        tracing::debug!(
                            "P2P retry loop for '{}': state={:?}, enabled={}, exiting",
                            peer_id, conn.state, conn.p2p_retry_enabled
                        );
                        return;
                    }
                    (true, conn.remote_candidates.clone(), conn.session_id.clone())
                } else {
                    return;
                }
            };

            if !should_retry || remote_candidates.is_empty() {
                continue;
            }

            tracing::info!("P2P retry attempt for '{}'...", peer_id);

            // Run a short hole punch attempt (3s timeout, no dynamic candidate feed)
            let (_probe_tx, probe_rx) = mpsc::unbounded_channel();
            let (_cand_tx, candidate_rx) = mpsc::unbounded_channel();

            let result = punch::run_hole_punch(
                manager.socket.clone(),
                remote_candidates,
                &session_id,
                Duration::from_secs(3),
                probe_rx,
                candidate_rx,
            )
            .await;

            match result {
                Ok(punch_result) => {
                    tracing::info!(
                        "P2P retry succeeded for '{}': remote_addr={}",
                        peer_id, punch_result.remote_addr
                    );

                    // Seamlessly switch from TURN to direct P2P
                    let switched = {
                        let mut connections = manager.connections.lock();
                        if let Some(conn) = connections.get_mut(&peer_id) {
                            if conn.state == ConnectionState::Relayed {
                                if let Some(session) = &conn.kcp_session {
                                    session.switch_remote(punch_result.remote_addr);
                                    session.disable_turn_relay();
                                    session.stats.is_relayed.store(
                                        false,
                                        std::sync::atomic::Ordering::Relaxed,
                                    );
                                }
                                conn.remote_addr = Some(punch_result.remote_addr);
                                conn.state = ConnectionState::Connected;
                                // Clear retry task reference (we're exiting the loop)
                                conn.p2p_retry_task = None;
                                true
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    };

                    if switched {
                        manager.notify_state(&peer_id, ConnectionState::Connected);
                    }
                    return; // Success — exit retry loop
                }
                Err(e) => {
                    tracing::debug!("P2P retry failed for '{}': {}", peer_id, e);
                    // Continue loop — will retry after 5s
                }
            }
        }
    }

    /// Enable/disable FEC for a peer session (with automatic peer notification).
    pub fn enable_fec(&self, remote_peer_id: &str, enabled: bool) -> Result<(), P2pError> {
        let session = {
            let connections = self.connections.lock();
            let conn = connections
                .get(remote_peer_id)
                .ok_or_else(|| P2pError::PeerNotFound(remote_peer_id.to_string()))?;
            conn.kcp_session.as_ref().ok_or(P2pError::NotConnected)?.clone()
        };
        // FEC can be applied locally immediately — each packet carries a flag byte
        // that tells the decoder whether FEC is active, so no transition needed.
        session.pipeline().enable_fec(enabled);
        // Notify remote peer to match
        let action = if enabled { negotiation::ACTION_ENABLE } else { negotiation::ACTION_DISABLE };
        let msg = negotiation::build_config_request(negotiation::FEATURE_FEC, action, None);
        self.send_control_raw(&session, &msg)
    }

    /// Enable encryption for a peer session (auto-generates key, negotiates with peer).
    pub fn enable_encryption(&self, remote_peer_id: &str) -> Result<(), P2pError> {
        let session = {
            let connections = self.connections.lock();
            let conn = connections
                .get(remote_peer_id)
                .ok_or_else(|| P2pError::PeerNotFound(remote_peer_id.to_string()))?;
            conn.kcp_session.as_ref().ok_or(P2pError::NotConnected)?.clone()
        };
        // Generate random 32-byte key
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        // Load key for transition: cipher loaded but encrypt() still sends plaintext.
        // This allows us to decrypt the remote peer's encrypted Ack.
        session.pipeline().load_encryption_key_for_transition(&key);
        // Send ConfigRequest with key (sent as plaintext since encryption not yet enabled)
        let msg = negotiation::build_config_request(
            negotiation::FEATURE_ENCRYPTION,
            negotiation::ACTION_ENABLE,
            Some(&key),
        );
        self.send_control_raw(&session, &msg)
    }

    /// Disable encryption for a peer session (with automatic peer notification).
    pub fn disable_encryption(&self, remote_peer_id: &str) -> Result<(), P2pError> {
        let session = {
            let connections = self.connections.lock();
            let conn = connections
                .get(remote_peer_id)
                .ok_or_else(|| P2pError::PeerNotFound(remote_peer_id.to_string()))?;
            conn.kcp_session.as_ref().ok_or(P2pError::NotConnected)?.clone()
        };
        // Send disable request first (while encryption is still active on both sides)
        let msg = negotiation::build_config_request(
            negotiation::FEATURE_ENCRYPTION,
            negotiation::ACTION_DISABLE,
            None,
        );
        self.send_control_raw(&session, &msg)
    }

    /// Enable/disable DNS disguise for a peer session (with automatic peer notification).
    pub fn enable_dns_disguise(
        &self,
        remote_peer_id: &str,
        enabled: bool,
    ) -> Result<(), P2pError> {
        let session = {
            let connections = self.connections.lock();
            let conn = connections
                .get(remote_peer_id)
                .ok_or_else(|| P2pError::PeerNotFound(remote_peer_id.to_string()))?;
            conn.kcp_session.as_ref().ok_or(P2pError::NotConnected)?.clone()
        };
        let action = if enabled { negotiation::ACTION_ENABLE } else { negotiation::ACTION_DISABLE };
        let msg = negotiation::build_config_request(negotiation::FEATURE_DNS_DISGUISE, action, None);
        self.send_control_raw(&session, &msg)
    }

    // --- Internal control message helpers ---

    /// Send a raw control message through the KCP session.
    fn send_control_raw(&self, session: &Arc<KcpSession>, msg: &[u8]) -> Result<(), P2pError> {
        let mut framed = Vec::with_capacity(1 + msg.len());
        framed.push(negotiation::FRAME_CONTROL);
        framed.extend_from_slice(msg);
        session.send(&framed).map_err(P2pError::Kcp)
    }

    /// Handle an incoming control message from a peer.
    fn handle_control_message(&self, peer_id: &str, data: &[u8]) {
        match negotiation::parse_control_message(data) {
            Ok(negotiation::ControlMessage::ConfigRequest(req)) => {
                self.handle_config_request(peer_id, req);
            }
            Ok(negotiation::ControlMessage::ConfigAck(ack)) => {
                self.handle_config_ack(peer_id, ack);
            }
            Ok(negotiation::ControlMessage::KeepalivePing) => {
                // Respond with pong
                let session = {
                    let connections = self.connections.lock();
                    connections.get(peer_id)
                        .and_then(|c| c.kcp_session.as_ref().cloned())
                };
                if let Some(session) = session {
                    let pong = negotiation::build_keepalive_pong();
                    let _ = self.send_control_raw(&session, &pong);
                    tracing::trace!("Keepalive ping from '{}', sent pong", peer_id);
                }
            }
            Ok(negotiation::ControlMessage::KeepalivePong) => {
                // Keepalive pong received — no action needed
                tracing::trace!("Keepalive pong from '{}'", peer_id);
            }
            Err(e) => {
                tracing::warn!("Invalid control message from '{}': {}", peer_id, e);
            }
        }
    }

    /// Handle a ConfigRequest from a remote peer.
    fn handle_config_request(&self, peer_id: &str, req: negotiation::ConfigRequest) {
        let session = {
            let connections = self.connections.lock();
            let conn = match connections.get(peer_id) {
                Some(c) => c,
                None => return,
            };
            match conn.kcp_session.as_ref() {
                Some(s) => s.clone(),
                None => return,
            }
        };

        match (req.feature, req.action) {
            (negotiation::FEATURE_FEC, negotiation::ACTION_ENABLE) => {
                session.pipeline().enable_fec(true);
                tracing::info!("FEC enabled by remote peer '{}'", peer_id);
                let ack = negotiation::build_config_ack(
                    req.seq, negotiation::FEATURE_FEC,
                    negotiation::ACTION_ENABLE, negotiation::STATUS_OK,
                );
                let _ = self.send_control_raw(&session, &ack);
            }
            (negotiation::FEATURE_FEC, negotiation::ACTION_DISABLE) => {
                session.pipeline().enable_fec(false);
                tracing::info!("FEC disabled by remote peer '{}'", peer_id);
                let ack = negotiation::build_config_ack(
                    req.seq, negotiation::FEATURE_FEC,
                    negotiation::ACTION_DISABLE, negotiation::STATUS_OK,
                );
                let _ = self.send_control_raw(&session, &ack);
            }
            (negotiation::FEATURE_ENCRYPTION, negotiation::ACTION_ENABLE) => {
                if let Some(key) = req.key {
                    // Enable encryption with the received key
                    session.pipeline().enable_encryption(&key);
                    // Enter transition mode: accept both plaintext and encrypted
                    // for a short window while the initiator switches over
                    session.pipeline().set_crypto_transition(true);
                    tracing::info!("Encryption enabled by remote peer '{}'", peer_id);
                    // Send Ack (now encrypted since we just enabled encryption)
                    let ack = negotiation::build_config_ack(
                        req.seq, negotiation::FEATURE_ENCRYPTION,
                        negotiation::ACTION_ENABLE, negotiation::STATUS_OK,
                    );
                    let _ = self.send_control_raw(&session, &ack);
                    // Exit transition mode after 2 seconds
                    let pipeline = session.pipeline().clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_secs(2)).await;
                        pipeline.set_crypto_transition(false);
                        tracing::debug!("Crypto transition mode ended");
                    });
                } else {
                    tracing::warn!("Encryption request from '{}' missing key", peer_id);
                }
            }
            (negotiation::FEATURE_ENCRYPTION, negotiation::ACTION_DISABLE) => {
                // Enter transition mode first, then disable after Ack
                session.pipeline().set_crypto_transition(true);
                let ack = negotiation::build_config_ack(
                    req.seq, negotiation::FEATURE_ENCRYPTION,
                    negotiation::ACTION_DISABLE, negotiation::STATUS_OK,
                );
                let _ = self.send_control_raw(&session, &ack);
                // Disable after a short delay to let in-flight encrypted packets arrive
                let pipeline = session.pipeline().clone();
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    pipeline.disable_encryption();
                    tracing::info!("Encryption disabled after transition");
                });
            }
            (negotiation::FEATURE_DNS_DISGUISE, negotiation::ACTION_ENABLE) => {
                session.pipeline().enable_dns_disguise(true);
                session.pipeline().set_dns_transition(true);
                tracing::info!("DNS disguise enabled by remote peer '{}'", peer_id);
                let ack = negotiation::build_config_ack(
                    req.seq, negotiation::FEATURE_DNS_DISGUISE,
                    negotiation::ACTION_ENABLE, negotiation::STATUS_OK,
                );
                let _ = self.send_control_raw(&session, &ack);
                let pipeline = session.pipeline().clone();
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    pipeline.set_dns_transition(false);
                    tracing::debug!("DNS transition mode ended");
                });
            }
            (negotiation::FEATURE_DNS_DISGUISE, negotiation::ACTION_DISABLE) => {
                session.pipeline().set_dns_transition(true);
                let ack = negotiation::build_config_ack(
                    req.seq, negotiation::FEATURE_DNS_DISGUISE,
                    negotiation::ACTION_DISABLE, negotiation::STATUS_OK,
                );
                let _ = self.send_control_raw(&session, &ack);
                let pipeline = session.pipeline().clone();
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    pipeline.enable_dns_disguise(false);
                    pipeline.set_dns_transition(false);
                    tracing::info!("DNS disguise disabled after transition");
                });
            }
            _ => {
                tracing::warn!(
                    "Unknown config request from '{}': feature={}, action={}",
                    peer_id, req.feature, req.action
                );
            }
        }
    }

    /// Handle a ConfigAck from a remote peer.
    fn handle_config_ack(&self, peer_id: &str, ack: negotiation::ConfigAck) {
        if ack.status != negotiation::STATUS_OK {
            tracing::warn!(
                "Config rejected by '{}': feature={}, action={}, status={}",
                peer_id, ack.feature, ack.action, ack.status
            );
            return;
        }

        let session = {
            let connections = self.connections.lock();
            let conn = match connections.get(peer_id) {
                Some(c) => c,
                None => return,
            };
            match conn.kcp_session.as_ref() {
                Some(s) => s.clone(),
                None => return,
            }
        };

        match (ack.feature, ack.action) {
            (negotiation::FEATURE_FEC, _) => {
                // FEC was already applied locally when the request was sent
                tracing::debug!("FEC config ack from '{}'", peer_id);
            }
            (negotiation::FEATURE_ENCRYPTION, negotiation::ACTION_ENABLE) => {
                // Remote peer has enabled encryption. Promote our transition key
                // to fully enabled (start sending encrypted).
                session.pipeline().enable_encryption_from_transition();
                tracing::info!("Encryption negotiation complete with '{}'", peer_id);
            }
            (negotiation::FEATURE_ENCRYPTION, negotiation::ACTION_DISABLE) => {
                // Remote peer acknowledged disable. Now disable locally.
                session.pipeline().disable_encryption();
                tracing::info!("Encryption disabled with '{}'", peer_id);
            }
            (negotiation::FEATURE_DNS_DISGUISE, negotiation::ACTION_ENABLE) => {
                // Remote peer has enabled DNS disguise. Enable locally.
                session.pipeline().enable_dns_disguise(true);
                tracing::info!("DNS disguise negotiation complete with '{}'", peer_id);
            }
            (negotiation::FEATURE_DNS_DISGUISE, negotiation::ACTION_DISABLE) => {
                session.pipeline().enable_dns_disguise(false);
                tracing::info!("DNS disguise disabled with '{}'", peer_id);
            }
            _ => {
                tracing::debug!("Unhandled config ack from '{}'", peer_id);
            }
        }
    }

    pub fn switch_remote(
        &self,
        remote_peer_id: &str,
        new_addr: SocketAddr,
        is_relay: bool,
    ) -> Result<(), P2pError> {
        let mut connections = self.connections.lock();
        let conn = connections
            .get_mut(remote_peer_id)
            .ok_or_else(|| P2pError::PeerNotFound(remote_peer_id.to_string()))?;
        let session = conn.kcp_session.as_ref().ok_or(P2pError::NotConnected)?;
        session.switch_remote(new_addr);
        session
            .stats
            .is_relayed
            .store(is_relay, std::sync::atomic::Ordering::Relaxed);
        conn.state = if is_relay {
            ConnectionState::Relayed
        } else {
            ConnectionState::Connected
        };
        conn.remote_addr = Some(new_addr);
        let new_state = conn.state.clone();
        drop(connections);
        self.notify_state(remote_peer_id, new_state);
        Ok(())
    }

    // =========================================================================
    // Internal packet handlers
    // =========================================================================

    /// Route a punch probe packet to the correct connection's probe channel.
    fn handle_punch_probe(&self, data: &[u8], from_addr: SocketAddr) {
        let session_hash = match punch::parse_probe(data) {
            Some(info) => info.session_hash,
            None => return,
        };

        let connections = self.connections.lock();
        for (peer_id, conn) in connections.iter() {
            if conn.session_hash == session_hash {
                if let Some(probe_tx) = &conn.probe_tx {
                    let _ = probe_tx.send((data.to_vec(), from_addr));
                    return;
                } else {
                    tracing::trace!(
                        "Probe for '{}' but no probe channel (state={:?})",
                        peer_id,
                        conn.state
                    );
                    return;
                }
            }
        }
        tracing::trace!(
            "Probe from {} with unknown session hash {:?}",
            from_addr,
            session_hash
        );
    }

    fn handle_kcp_packet(&self, data: &[u8], from_addr: SocketAddr, conv_id: u32) {
        // Collect decoded KCP messages while holding connections lock,
        // then release the lock BEFORE invoking callbacks or processing control msgs.
        // This prevents deadlock if the callback calls p2p_send/p2p_disconnect.
        let decoded_packets: Vec<(String, Vec<u8>)> = {
            let connections = self.connections.lock();
            let mut result = Vec::new();
            let mut matched = false;

            // M4: Fast path using conv_id index for O(1) lookup
            if let Some(peer_id) = self.conv_id_index.lock().get(&conv_id).cloned() {
                if let Some(conn) = connections.get(&peer_id) {
                    if let Some(session) = &conn.kcp_session {
                        if let Err(e) = session.input_wire(data) {
                            tracing::warn!("KCP input error from {}: {}", peer_id, e);
                        } else {
                            session.stats.touch_recv_time();
                        }
                        while let Some(d) = session.recv() {
                            result.push((peer_id.clone(), d));
                        }
                        matched = true;
                    }
                }
            }

            // Fallback: linear scan (conv_id index may not be populated yet
            // if the session was just created or if the index entry was stale)
            if !matched {
                for (peer_id, conn) in connections.iter() {
                    if let Some(session) = &conn.kcp_session {
                        if session.conv_id() == conv_id {
                            if let Err(e) = session.input_wire(data) {
                                tracing::warn!("KCP input error from {}: {}", peer_id, e);
                            } else {
                                session.stats.touch_recv_time();
                            }
                            while let Some(d) = session.recv() {
                                result.push((peer_id.clone(), d));
                            }
                            matched = true;
                            break;
                        }
                    }
                }
            }

            // Slow path: try each session (wrong conv_id extraction due to
            // encryption or DNS disguise changing header layout).
            // First do pipeline decoding, then check the KCP conv_id in the
            // decoded data to avoid injecting data into the wrong session.
            if !matched {
                for (peer_id, conn) in connections.iter() {
                    if let Some(session) = &conn.kcp_session {
                        let decoded_pkts = session.pipeline_decode(data);
                        if decoded_pkts.is_empty() {
                            continue;
                        }
                        // Check KCP conv_id in decoded packet header before input
                        let mut session_matched = false;
                        for pkt in &decoded_pkts {
                            if pkt.len() >= 4 {
                                let pkt_conv = u32::from_le_bytes([pkt[0], pkt[1], pkt[2], pkt[3]]);
                                if pkt_conv == session.conv_id() {
                                    session_matched = true;
                                    break;
                                }
                            }
                        }
                        if session_matched {
                            let mut any_ok = false;
                            for pkt in decoded_pkts {
                                if let Err(e) = session.input(&pkt) {
                                    tracing::warn!("KCP input error from {}: {}", peer_id, e);
                                } else {
                                    any_ok = true;
                                }
                            }
                            if any_ok {
                                session.stats.touch_recv_time();
                            }
                            while let Some(d) = session.recv() {
                                result.push((peer_id.clone(), d));
                            }
                            matched = true;
                            break;
                        }
                    }
                }
            }

            if !matched {
                tracing::debug!(
                    "KCP packet with unknown conv_id {} from {} ({} bytes)",
                    conv_id, from_addr, data.len(),
                );
            }

            result
        };
        // connections lock released — safe to invoke callbacks

        self.dispatch_kcp_messages(decoded_packets);
    }

    /// Handle an opaque KCP pipeline packet (conv_id not extractable due to
    /// encryption or DNS disguise). Goes directly to slow path: tries each
    /// session's input_wire() which runs the full pipeline (DNS unwrap →
    /// Decrypt → FEC decode → KCP input with internal conv_id validation).
    fn handle_kcp_opaque(&self, data: &[u8], from_addr: SocketAddr) {
        // Collect decoded data while holding lock, invoke callback after release.
        let decoded_packets: Vec<(String, Vec<u8>)> = {
            let connections = self.connections.lock();
            let mut result = Vec::new();
            let mut matched = false;

            for (peer_id, conn) in connections.iter() {
                if let Some(session) = &conn.kcp_session {
                    // Decode through pipeline first, then verify conv_id before
                    // injecting into KCP — prevents misrouting to wrong session.
                    let decoded_pkts = session.pipeline_decode(data);
                    if decoded_pkts.is_empty() {
                        continue;
                    }
                    let mut session_matched = false;
                    for pkt in &decoded_pkts {
                        if pkt.len() >= 4 {
                            let pkt_conv = u32::from_le_bytes([pkt[0], pkt[1], pkt[2], pkt[3]]);
                            if pkt_conv == session.conv_id() {
                                session_matched = true;
                                break;
                            }
                        }
                    }
                    if session_matched {
                        let mut any_ok = false;
                        for pkt in decoded_pkts {
                            if let Err(e) = session.input(&pkt) {
                                tracing::warn!("KCP input error from {}: {}", peer_id, e);
                            } else {
                                any_ok = true;
                            }
                        }
                        if any_ok {
                            session.stats.touch_recv_time();
                        }
                        while let Some(d) = session.recv() {
                            result.push((peer_id.clone(), d));
                        }
                        matched = true;
                        break;
                    }
                }
            }

            if !matched {
                tracing::trace!(
                    "Opaque KCP packet from {} ({} bytes) matched no session",
                    from_addr, data.len(),
                );
            }

            result
        };
        // connections lock released — safe to invoke callbacks

        self.dispatch_kcp_messages(decoded_packets);
    }

    /// Handle TURN ChannelData: unwrap the inner payload and feed to KCP session.
    fn handle_turn_channel_data(&self, data: &[u8], channel: u16) {
        // Unwrap ChannelData: 2 bytes channel + 2 bytes length + payload
        if data.len() < 4 {
            return;
        }
        let length = u16::from_be_bytes([data[2], data[3]]) as usize;
        if data.len() < 4 + length {
            return;
        }
        let inner = &data[4..4 + length];

        // Collect decoded data while holding lock, invoke callback after release.
        let decoded_packets: Vec<(String, Vec<u8>)> = {
            let connections = self.connections.lock();
            let mut result = Vec::new();
            let mut matched = false;

            for (peer_id, conn) in connections.iter() {
                if conn.turn_channel == Some(channel) {
                    if let Some(session) = &conn.kcp_session {
                        if let Err(e) = session.input_wire(inner) {
                            tracing::warn!("KCP input via TURN for '{}': {}", peer_id, e);
                        } else {
                            session.stats.touch_recv_time();
                        }
                        while let Some(d) = session.recv() {
                            result.push((peer_id.clone(), d));
                        }
                        matched = true;
                        break;
                    }
                }
            }

            if !matched {
                tracing::trace!(
                    "TURN ChannelData on channel 0x{:04X} ({} bytes) — no matching session",
                    channel, length
                );
            }

            result
        };
        // connections lock released — safe to invoke callbacks

        self.dispatch_kcp_messages(decoded_packets);
    }

    /// Dispatch decoded KCP messages: separate control messages from app data.
    ///
    /// Control messages (frame prefix 0x01) are handled internally.
    /// App data messages (frame prefix 0x00) are forwarded to `receive_cb`.
    fn dispatch_kcp_messages(&self, messages: Vec<(String, Vec<u8>)>) {
        for (peer_id, raw) in &messages {
            if raw.is_empty() {
                continue;
            }
            match raw[0] {
                negotiation::FRAME_APP_DATA => {
                    // Application data — strip prefix and forward to user callback
                    let app_data = &raw[1..];
                    if let Some(cb) = self.receive_cb.lock().as_ref() {
                        cb(peer_id, app_data);
                    }
                }
                negotiation::FRAME_CONTROL => {
                    // Control message — handle internally
                    self.handle_control_message(peer_id, &raw[1..]);
                }
                _ => {
                    // Unknown frame type — ignore
                    tracing::trace!(
                        "Unknown KCP frame type 0x{:02X} from '{}' ({} bytes)",
                        raw[0], peer_id, raw.len()
                    );
                }
            }
        }
    }

    // =========================================================================
    // Health monitoring & auto-reconnect
    // =========================================================================

    /// Start a background task that periodically checks connection health,
    /// sends keepalive probes, and triggers reconnection for dead connections.
    fn start_health_monitor(self: &Arc<Self>) {
        let manager = Arc::downgrade(self);
        let keepalive_interval = self.config.keepalive_interval;
        let dead_timeout = self.config.dead_timeout;
        // Check at half the keepalive interval for timely detection
        let check_interval = keepalive_interval / 2;

        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(check_interval);
            loop {
                interval.tick().await;
                let manager = match manager.upgrade() {
                    Some(m) => m,
                    None => return, // Manager dropped, exit
                };
                if manager.shutting_down.load(Relaxed) {
                    return;
                }
                manager.health_check(keepalive_interval, dead_timeout).await;
            }
        });
        *self.health_task.lock() = Some(handle);
    }

    /// Check all active connections for health, send keepalives, detect dead.
    async fn health_check(
        self: &Arc<Self>,
        keepalive_interval: Duration,
        dead_timeout: Duration,
    ) {
        enum HealthAction {
            SendKeepalive(Arc<KcpSession>),
            Dead,
        }

        // Collect actions under a single short lock
        let peer_actions: Vec<(String, HealthAction)> = {
            let connections = self.connections.lock();
            connections.iter().filter_map(|(peer_id, conn)| {
                // Only monitor active connections
                if conn.state != ConnectionState::Connected
                    && conn.state != ConnectionState::Relayed
                {
                    return None;
                }
                let session = conn.kcp_session.as_ref()?;
                let ms_since_recv = session.stats.ms_since_last_recv();
                let dead_ms = dead_timeout.as_millis() as u64;
                let keepalive_ms = keepalive_interval.as_millis() as u64;

                if ms_since_recv >= dead_ms {
                    Some((peer_id.clone(), HealthAction::Dead))
                } else if ms_since_recv >= keepalive_ms {
                    Some((peer_id.clone(), HealthAction::SendKeepalive(session.clone())))
                } else {
                    None
                }
            }).collect()
        };
        // Lock released — safe to call send() and initiate_reconnect()

        for (peer_id, action) in peer_actions {
            match action {
                HealthAction::SendKeepalive(session) => {
                    let ping = negotiation::build_keepalive_ping();
                    let _ = self.send_control_raw(&session, &ping);
                    tracing::trace!("Sent keepalive ping to '{}'", peer_id);
                }
                HealthAction::Dead => {
                    tracing::warn!(
                        "Connection to '{}' dead (no data for {:?}), initiating reconnect",
                        peer_id, dead_timeout
                    );
                    self.initiate_reconnect(&peer_id).await;
                }
            }
        }
    }

    /// Initiate automatic reconnection to a peer whose connection has died.
    async fn initiate_reconnect(self: &Arc<Self>, peer_id: &str) {
        if self.shutting_down.load(Relaxed) {
            return;
        }
        if !self.config.auto_reconnect {
            self.disconnect(peer_id);
            return;
        }

        // Check and increment reconnection attempts
        let attempt = {
            let mut rs = self.reconnect_state.lock();
            let state = rs.entry(peer_id.to_string()).or_insert(ReconnectState {
                attempts: 0,
                was_connected: true,
            });
            state.attempts += 1;
            state.attempts
        };

        if attempt > self.config.max_reconnect_attempts {
            tracing::warn!(
                "Max reconnect attempts ({}) reached for '{}', disconnecting",
                self.config.max_reconnect_attempts, peer_id
            );
            self.reconnect_state.lock().remove(peer_id);
            self.disconnect(peer_id);
            return;
        }

        // Check that signaling is available
        let has_signaling = self.signaling_tx.lock().is_some();
        if !has_signaling {
            tracing::warn!(
                "Cannot reconnect to '{}': signaling is down, waiting for signaling recovery",
                peer_id
            );
            // Don't disconnect — signaling reconnect may restore it
            return;
        }

        // Clean up old connection state, preserving reconnect metadata
        {
            let mut connections = self.connections.lock();
            if let Some(conn) = connections.get_mut(peer_id) {
                if let Some(h) = conn.punch_task.take() {
                    h.abort();
                }
                if let Some(h) = conn.p2p_retry_task.take() {
                    h.abort();
                }
                if let Some(session) = conn.kcp_session.take() {
                    self.conv_id_index.lock().remove(&session.conv_id());
                }
                conn.probe_tx = None;
                conn.candidate_tx = None;
                conn.local_candidates.clear();
                conn.remote_candidates.clear();
                conn.answer_received = false;
                conn.turn_allocation = None;
                conn.turn_channel = None;
                conn.remote_addr = None;
                conn.state = ConnectionState::Reconnecting;
            } else {
                return;
            }
        }

        self.notify_state(peer_id, ConnectionState::Reconnecting);
        tracing::info!(
            "Reconnect attempt {}/{} for '{}'",
            attempt, self.config.max_reconnect_attempts, peer_id
        );

        // Generate new session and send ConnectRequest
        let session_id = uuid::Uuid::new_v4().to_string();
        let session_hash = punch::compute_session_hash(&session_id);

        {
            let signaling = self.signaling_tx.lock();
            if let Some(signaling) = signaling.as_ref() {
                if signaling.send(SignalingMessage::ConnectRequest(ConnectRequestPayload {
                    target_peer_id: peer_id.to_string(),
                    session_id: session_id.clone(),
                })).is_err() {
                    tracing::warn!("Failed to send ConnectRequest for reconnect to '{}'", peer_id);
                    return;
                }
            } else {
                return;
            }
        }

        // Update PeerConnection with new session info
        {
            let mut connections = self.connections.lock();
            if let Some(conn) = connections.get_mut(peer_id) {
                conn.session_id = session_id;
                conn.session_hash = session_hash;
                conn.is_initiator = true;
                conn.reverse_attempted = false;
                conn.state = ConnectionState::Gathering;
            }
        }

        self.notify_state(peer_id, ConnectionState::Gathering);

        // Follow the standard connection flow
        if let Err(e) = self.gather_and_send_candidates(peer_id).await {
            tracing::error!("Reconnect candidate gathering failed for '{}': {}", peer_id, e);
            return;
        }
        self.spawn_reflexive_gathering(peer_id);
        self.try_start_punching(peer_id).await;
        self.spawn_gathering_timeout(peer_id);
    }

    /// Called when the signaling WebSocket connection is lost.
    /// Attempts reconnection with exponential backoff.
    async fn on_signaling_lost(self: &Arc<Self>) {
        if self.shutting_down.load(Relaxed) {
            return;
        }

        // Clear old sender so health monitor knows signaling is down
        *self.signaling_tx.lock() = None;
        if let Some(h) = self.signaling_io_task.lock().take() {
            h.abort();
        }

        let peer_id = match self.peer_id.lock().clone() {
            Some(id) => id,
            None => return, // Never registered
        };

        let max_attempts = 10u32;
        for attempt in 1..=max_attempts {
            if self.shutting_down.load(Relaxed) {
                tracing::info!("Manager shutting down, aborting signaling reconnection");
                return;
            }

            // Exponential backoff: 1s, 2s, 4s, 8s, 16s, 30s, 30s, ...
            let delay = Duration::from_secs(
                (1u64 << (attempt - 1).min(4)).min(30)
            );
            tracing::info!(
                "Signaling reconnect attempt {}/{} in {:?}",
                attempt, max_attempts, delay
            );
            tokio::time::sleep(delay).await;

            if self.shutting_down.load(Relaxed) {
                return;
            }

            // Try to connect and re-register
            match p2p_signaling_client::SignalingClient::connect(&self.config.signaling_url).await {
                Ok(mut client) => {
                    match client.register(&peer_id).await {
                        Ok(()) => {
                            tracing::info!(
                                "Signaling reconnected and re-registered as '{}'",
                                peer_id
                            );
                            let (sender, receiver, io_task) = client.into_parts();
                            *self.signaling_tx.lock() = Some(sender);
                            *self.signaling_io_task.lock() = io_task;

                            // Start a new signaling handler (this task will then exit)
                            self.start_signaling_handler(receiver);

                            // After signaling is restored, attempt to reconnect any
                            // peers that were waiting for signaling
                            let peers_to_reconnect: Vec<String> = {
                                let connections = self.connections.lock();
                                connections.iter()
                                    .filter(|(_, c)| c.state == ConnectionState::Reconnecting
                                        || c.state == ConnectionState::Connected
                                        || c.state == ConnectionState::Relayed)
                                    .filter(|(_, c)| c.kcp_session.is_none())
                                    .map(|(pid, _)| pid.clone())
                                    .collect()
                            };
                            for pid in peers_to_reconnect {
                                self.initiate_reconnect(&pid).await;
                            }
                            return;
                        }
                        Err(e) => {
                            tracing::warn!("Signaling re-registration failed: {}", e);
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Signaling reconnect failed: {}", e);
                }
            }
        }

        tracing::error!(
            "Signaling reconnection failed after {} attempts, disconnecting all peers",
            max_attempts
        );
        // Give up — disconnect all peers
        let peer_ids: Vec<String> = {
            self.connections.lock().keys().cloned().collect()
        };
        for pid in peer_ids {
            self.disconnect(&pid);
        }
    }

    fn notify_state(&self, peer_id: &str, state: ConnectionState) {
        if let Some(cb) = self.state_cb.lock().as_ref() {
            cb(peer_id, state);
        }
    }
}

impl Drop for ConnectionManager {
    fn drop(&mut self) {
        // shutdown() aborts recv_task, signaling_task, and all punch tasks.
        // Fire-and-forget tasks (STUN/TURN/gathering timeout) use Weak<Self>
        // so they don't prevent Drop from firing and will exit gracefully
        // when their Weak::upgrade() returns None.
        self.shutdown();
    }
}
