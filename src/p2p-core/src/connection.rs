use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use rand::{RngCore, rngs::OsRng};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use p2p_signaling_client::SignalingSender;
use p2p_signaling_proto::*;
use p2p_stun::{StunClient, StunResponseRouter};
use p2p_turn::TurnCredentials;

use crate::candidate::{Candidate, gather_host_candidates};
use crate::config::P2pConfig;
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

/// Manages all P2P connections.
pub struct ConnectionManager {
    config: P2pConfig,
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
}

impl ConnectionManager {
    /// Create a new ConnectionManager with the given configuration.
    pub async fn new(config: P2pConfig) -> Result<Arc<Self>, P2pError> {
        let socket = Arc::new(DualStackSocket::bind(0, config.enable_ipv6).await?);
        let stun_router = Arc::new(StunResponseRouter::new());

        let manager = Arc::new(Self {
            config,
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
        });

        // Start the UDP receive loop
        manager.start_recv_loop();

        Ok(manager)
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
    pub async fn connect(self: &Arc<Self>, remote_peer_id: &str) -> Result<(), P2pError> {
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
                },
            );
        }

        self.notify_state(remote_peer_id, ConnectionState::Gathering);

        // Send host candidates immediately (no I/O, instant)
        self.gather_and_send_candidates(remote_peer_id).await?;

        // Spawn background STUN/TURN gathering — results trickle in asynchronously
        self.spawn_reflexive_gathering(remote_peer_id);

        // Try to start punching now that we have local host candidates.
        // If the remote Answer and candidates already arrived, punch starts immediately
        // without waiting for STUN results.
        self.try_start_punching(remote_peer_id).await;

        // Spawn a gathering timeout watchdog: if we're still in Gathering after
        // 10 seconds (waiting for Answer or remote candidates), fail the connection.
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
            // M4: Remove conv_id index entry
            if let Some(session) = &conn.kcp_session {
                self.conv_id_index.lock().remove(&session.conv_id());
            }
            drop(connections);
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
            tracing::warn!("Signaling receiver closed");
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

        // Ask the application whether to accept
        let accepted = {
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
    async fn trickle_local_candidate(self: &Arc<Self>, peer_id: &str, candidate: Candidate) {
        // 1. Store the candidate (with dedup)
        let session_id = {
            let mut connections = self.connections.lock();
            if let Some(conn) = connections.get_mut(peer_id) {
                if conn.local_candidates.iter().any(|c| c.address == candidate.address) {
                    return;
                }
                conn.local_candidates.push(candidate.clone());
                conn.session_id.clone()
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

        // 3. Try to start punching (if not already started and conditions now met)
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
        if let Some(turn_config) = self.config.turn_server.clone() {
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
        let should_start = {
            let mut connections = self.connections.lock();
            if let Some(conn) = connections.get_mut(peer_id) {
                if conn.state == ConnectionState::Gathering
                    && !conn.local_candidates.is_empty()
                    && !conn.remote_candidates.is_empty()
                    && conn.answer_received
                    && conn.punch_task.is_none()
                {
                    conn.state = ConnectionState::Punching;
                    true
                } else {
                    false
                }
            } else {
                false
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
        let timeout = self.config.punch_timeout;

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
                }
                // M4: Register conv_id → peer_id mapping for fast packet routing
                self.conv_id_index.lock().insert(conv_id, peer_id.to_string());
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
                            for pkt in decoded_pkts {
                                if let Err(e) = session.input(&pkt) {
                                    tracing::warn!("KCP input error from {}: {}", peer_id, e);
                                }
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
                        for pkt in decoded_pkts {
                            if let Err(e) = session.input(&pkt) {
                                tracing::warn!("KCP input error from {}: {}", peer_id, e);
                            }
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
