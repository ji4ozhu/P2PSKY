use std::ffi::c_char;

/// Opaque handle to the P2P library instance.
#[repr(C)]
pub struct P2pHandle {
    _private: [u8; 0],
}

/// Configuration for P2P initialization.
#[repr(C)]
pub struct P2pConfigC {
    /// WebSocket URL of the signaling server (e.g., "ws://localhost:8080")
    pub signaling_url: *const c_char,
    /// STUN server address (NULL = use defaults)
    pub stun_server: *const c_char,
    /// TURN server address (NULL = no TURN)
    pub turn_server: *const c_char,
    /// TURN username (NULL if no TURN)
    pub turn_username: *const c_char,
    /// TURN password (NULL if no TURN)
    pub turn_password: *const c_char,
    /// Whether to enable IPv6 dual-stack
    pub enable_ipv6: bool,
    /// KCP mode: 0 = Normal, 1 = Fast, 2 = Turbo
    pub kcp_mode: u32,
}

/// Connection state reported via callback.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum P2pConnectionStateC {
    Connecting = 0,
    Connected = 1,
    Relayed = 2,
    Reconnecting = 3,
    Disconnected = 4,
    Gathering = 5,
    Punching = 6,
}

/// Full connection statistics snapshot (matches IUdxInfo-style interface).
#[repr(C)]
#[derive(Debug, Clone)]
pub struct P2pStatsC {
    // --- Cumulative data ---
    /// Total bytes received (application level)
    pub bytes_read: u64,
    /// Total bytes sent (application level)
    pub bytes_written: u64,
    /// Total raw UDP packets received
    pub packets_recv: u64,
    /// Total raw UDP packets sent
    pub packets_sent: u64,
    /// Total retransmitted packets
    pub packets_retransmit: u64,
    /// Total FEC parity packets sent
    pub fec_packets_sent: u64,
    /// Total packets recovered by FEC
    pub fec_recoveries: u64,

    // --- Real-time metrics ---
    /// Current smoothed RTT in milliseconds
    pub rtt_ms: f32,
    /// Minimum observed RTT in milliseconds
    pub rtt_min_ms: f32,
    /// RTT jitter in microseconds
    pub rtt_var_us: u32,
    /// Current retransmission timeout in milliseconds
    pub rto_ms: u32,
    /// Current packet loss percentage (0.0 - 100.0)
    pub loss_percent: f32,

    // --- Speed ---
    /// Current receive speed in bytes/sec
    pub speed_recv: u64,
    /// Current send speed in bytes/sec
    pub speed_send: u64,

    // --- Window / buffer ---
    /// Current send window size (packets)
    pub send_window: u32,
    /// Current receive window size (packets)
    pub recv_window: u32,
    /// Packets sent but not yet acknowledged
    pub inflight: u32,
    /// Packets in send buffer
    pub send_queue_len: u32,
    /// Packets in receive buffer
    pub recv_queue_len: u32,

    // --- Feature flags ---
    /// Whether currently relayed through TURN
    pub is_relayed: bool,
    /// Whether FEC is enabled
    pub fec_enabled: bool,
    /// Whether encryption is enabled
    pub encryption_enabled: bool,
    /// Whether DNS disguise is enabled
    pub dns_disguise_enabled: bool,

    // --- Connection address info ---
    /// Remote peer address as null-terminated string, e.g. "1.2.3.4:5678"
    pub remote_addr: [u8; 64],
    /// Local UDP port used for this connection
    pub local_port: u16,
}
