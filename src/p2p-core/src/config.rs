use std::time::Duration;

/// Configuration for the P2P library.
#[derive(Debug, Clone)]
pub struct P2pConfig {
    /// WebSocket URL of the signaling server (e.g., "ws://localhost:8080")
    pub signaling_url: String,
    /// STUN server addresses for NAT traversal
    pub stun_servers: Vec<String>,
    /// TURN server address (optional, for relay fallback)
    pub turn_server: Option<TurnConfig>,
    /// Whether to enable IPv6 (dual-stack)
    pub enable_ipv6: bool,
    /// KCP mode preset
    pub kcp_mode: KcpMode,
    /// Timeout for STUN binding requests
    pub stun_timeout: Duration,
    /// Timeout for hole punching attempts
    pub punch_timeout: Duration,
    /// Application-level keepalive interval
    pub keepalive_interval: Duration,
    /// Time without any response before considering the connection dead
    pub dead_timeout: Duration,
}

#[derive(Debug, Clone)]
pub struct TurnConfig {
    pub server_addr: String,
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KcpMode {
    /// Default mode: moderate latency, moderate bandwidth usage
    Normal,
    /// Fast mode: low latency, higher bandwidth usage (for gaming, realtime)
    Fast,
    /// Turbo mode: minimum latency, highest bandwidth usage
    Turbo,
}

impl Default for P2pConfig {
    fn default() -> Self {
        Self {
            signaling_url: "ws://localhost:8080".to_string(),
            stun_servers: vec![
                "stun.cloudflare.com:3478".to_string(),
                "stun.l.google.com:19302".to_string(),
                "stun.voip.blackberry.com:3478".to_string(),
                "stun.sipnet.com:3478".to_string(),
                "stun.f.haeder.net:3478".to_string(),
            ],
            turn_server: None,
            enable_ipv6: true,
            kcp_mode: KcpMode::Fast,
            stun_timeout: Duration::from_secs(3),
            punch_timeout: Duration::from_secs(15),
            keepalive_interval: Duration::from_secs(10),
            dead_timeout: Duration::from_secs(60),
        }
    }
}
