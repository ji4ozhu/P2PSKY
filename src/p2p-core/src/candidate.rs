use std::net::SocketAddr;
use p2p_signaling_proto::{CandidateType, IceCandidate, TransportProtocol};

/// A gathered candidate with its source information.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub candidate_type: CandidateType,
    pub address: SocketAddr,
    pub priority: u32,
}

impl Candidate {
    pub fn host(addr: SocketAddr) -> Self {
        Self {
            candidate_type: CandidateType::Host,
            address: addr,
            priority: Self::compute_priority(CandidateType::Host, addr),
        }
    }

    pub fn server_reflexive(addr: SocketAddr) -> Self {
        Self {
            candidate_type: CandidateType::ServerReflexive,
            address: addr,
            priority: Self::compute_priority(CandidateType::ServerReflexive, addr),
        }
    }

    pub fn peer_reflexive(addr: SocketAddr) -> Self {
        Self {
            candidate_type: CandidateType::PeerReflexive,
            address: addr,
            priority: Self::compute_priority(CandidateType::PeerReflexive, addr),
        }
    }

    pub fn relay(addr: SocketAddr) -> Self {
        Self {
            candidate_type: CandidateType::Relay,
            address: addr,
            priority: Self::compute_priority(CandidateType::Relay, addr),
        }
    }

    /// Create a Candidate from a signaling protocol IceCandidate.
    pub fn from_ice_candidate(ice: &IceCandidate) -> Option<Self> {
        let address: SocketAddr = parse_addr(&ice.address).ok()?;
        Some(Self {
            candidate_type: ice.candidate_type.clone(),
            address,
            priority: ice.priority,
        })
    }

    /// Convert to the signaling protocol's IceCandidate format.
    pub fn to_ice_candidate(&self) -> IceCandidate {
        IceCandidate {
            candidate_type: self.candidate_type.clone(),
            address: format_addr(&self.address),
            priority: self.priority,
            protocol: TransportProtocol::Udp,
        }
    }

    /// Compute candidate priority following ICE-like ordering:
    /// Host (126) > ServerReflexive (100) > Relay (0)
    /// IPv6 gets a small bonus over IPv4.
    fn compute_priority(candidate_type: CandidateType, addr: SocketAddr) -> u32 {
        let type_pref: u32 = match candidate_type {
            CandidateType::Host => 126,
            CandidateType::PeerReflexive => 110,
            CandidateType::ServerReflexive => 100,
            CandidateType::Relay => 0,
        };
        let ip_pref: u32 = if addr.is_ipv6() { 1 } else { 0 };
        // Priority formula: type_preference * 1000 + ip_preference
        type_pref * 1000 + ip_pref
    }
}

/// A pair of local and remote candidates for connectivity checking.
#[derive(Debug, Clone)]
pub struct CandidatePair {
    pub local: Candidate,
    pub remote: Candidate,
    pub priority: u64,
}

impl CandidatePair {
    pub fn new(local: Candidate, remote: Candidate) -> Self {
        // Combined priority: higher of (local, remote) * 2^32 + lower + tie-breaker
        let (g, d) = if local.priority >= remote.priority {
            (local.priority as u64, remote.priority as u64)
        } else {
            (remote.priority as u64, local.priority as u64)
        };
        let priority = (g << 32) + d * 2 + 1;
        Self {
            local,
            remote,
            priority,
        }
    }
}

/// Format a SocketAddr for the signaling protocol.
/// IPv6 addresses are formatted as "[::1]:port".
fn format_addr(addr: &SocketAddr) -> String {
    match addr {
        SocketAddr::V4(v4) => format!("{}:{}", v4.ip(), v4.port()),
        SocketAddr::V6(v6) => format!("[{}]:{}", v6.ip(), v6.port()),
    }
}

/// Parse an address string back to SocketAddr.
/// Handles both "1.2.3.4:5678" and "[::1]:5678" formats.
pub fn parse_addr(s: &str) -> Result<SocketAddr, std::net::AddrParseError> {
    s.parse()
}

/// Gather local host candidates from all network interfaces.
pub fn gather_host_candidates(port: u16) -> Vec<Candidate> {
    let mut candidates = Vec::new();

    // Use a simple approach: bind to 0.0.0.0 and [::] and detect local IPs
    // For a more thorough approach, we'd use platform-specific APIs to enumerate interfaces
    // For now, we rely on the OS to tell us our local addresses
    if let Ok(addrs) = local_ip_addresses() {
        for addr in addrs {
            let socket_addr = SocketAddr::new(addr, port);
            candidates.push(Candidate::host(socket_addr));
        }
    }

    candidates
}

/// Get local IP addresses (non-loopback, non-link-local).
///
/// Uses a multi-target probing approach: creates UDP sockets and "connects" to
/// well-known public IPs from different providers. This discovers all network
/// interfaces that have a default route. Each target IP may route through a
/// different interface (e.g., WiFi vs Ethernet vs VPN).
fn local_ip_addresses() -> std::io::Result<Vec<std::net::IpAddr>> {
    let mut addrs = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // IPv4: try multiple targets to discover different routes/interfaces
    let v4_targets = [
        "8.8.8.8:80",          // Google DNS
        "1.1.1.1:80",          // Cloudflare DNS
        "208.67.222.222:80",   // OpenDNS
        "114.114.114.114:80",  // China DNS (catches CN networks)
        "9.9.9.9:80",          // Quad9
    ];
    for target in &v4_targets {
        if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") {
            if socket.connect(target).is_ok() {
                if let Ok(local) = socket.local_addr() {
                    let ip = local.ip();
                    // Skip loopback
                    if ip.is_loopback() {
                        continue;
                    }
                    if seen.insert(ip) {
                        addrs.push(ip);
                    }
                }
            }
        }
    }

    // IPv6: try multiple targets
    let v6_targets = [
        "[2001:4860:4860::8888]:80",  // Google
        "[2606:4700:4700::1111]:80",  // Cloudflare
        "[2620:fe::fe]:80",           // Quad9
    ];
    for target in &v6_targets {
        if let Ok(socket) = std::net::UdpSocket::bind("[::]:0") {
            if socket.connect(target).is_ok() {
                if let Ok(local) = socket.local_addr() {
                    let ip = local.ip();
                    // Skip loopback and link-local
                    if ip.is_loopback() {
                        continue;
                    }
                    if let std::net::IpAddr::V6(v6) = ip {
                        // Skip link-local (fe80::/10)
                        if (v6.segments()[0] & 0xffc0) == 0xfe80 {
                            continue;
                        }
                    }
                    if seen.insert(ip) {
                        addrs.push(ip);
                    }
                }
            }
        }
    }

    Ok(addrs)
}
