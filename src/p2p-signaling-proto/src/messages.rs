use serde::{Deserialize, Serialize};

/// Top-level signaling message. Serialized as JSON over WebSocket text frames.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type", content = "payload")]
pub enum SignalingMessage {
    // === Client -> Server ===
    /// Register this peer with the signaling server.
    Register(RegisterPayload),
    /// Request a connection to a remote peer.
    ConnectRequest(ConnectRequestPayload),
    /// Send an ICE-like candidate to a remote peer (trickled).
    Candidate(CandidatePayload),
    /// Accept an incoming connection.
    Answer(AnswerPayload),
    /// Reject an incoming connection.
    Reject(RejectPayload),
    /// Request the remote peer to initiate a reverse connection attempt.
    ReverseConnect(ReverseConnectPayload),
    /// Heartbeat ping.
    Ping,
    /// Unregister from the signaling server.
    Unregister,

    // === Server -> Client ===
    /// Registration confirmed.
    Registered(RegisteredPayload),
    /// Incoming connection request from a remote peer.
    IncomingConnection(IncomingConnectionPayload),
    /// A candidate forwarded from a remote peer.
    CandidateForward(CandidatePayload),
    /// Connection accepted by the remote peer.
    AnswerForward(AnswerPayload),
    /// Connection rejected by the remote peer.
    Rejected(RejectedPayload),
    /// A peer has disconnected.
    PeerDisconnected(PeerDisconnectedPayload),
    /// Forwarded reverse connection request from a remote peer.
    ReverseConnectForward(ReverseConnectPayload),
    /// Heartbeat pong.
    Pong,
    /// Error from server.
    Error(ErrorPayload),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RegisterPayload {
    pub peer_id: String,
    pub protocol_version: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RegisteredPayload {
    pub peer_id: String,
    pub server_time: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ConnectRequestPayload {
    pub target_peer_id: String,
    pub session_id: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IncomingConnectionPayload {
    pub from_peer_id: String,
    pub session_id: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CandidatePayload {
    pub target_peer_id: String,
    pub session_id: String,
    pub candidate: IceCandidate,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IceCandidate {
    pub candidate_type: CandidateType,
    /// Address in "ip:port" format, e.g. "203.0.113.5:45678" or "[::1]:45678"
    pub address: String,
    pub priority: u32,
    pub protocol: TransportProtocol,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum CandidateType {
    /// Local network interface address.
    Host,
    /// Address as seen by a STUN server (external NAT mapping).
    ServerReflexive,
    /// Address discovered during connectivity checks (probe from unknown source).
    PeerReflexive,
    /// TURN relay address.
    Relay,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum TransportProtocol {
    Udp,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AnswerPayload {
    pub target_peer_id: String,
    pub session_id: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RejectPayload {
    pub target_peer_id: String,
    pub session_id: String,
    pub reason: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RejectedPayload {
    pub from_peer_id: String,
    pub session_id: String,
    pub reason: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ReverseConnectPayload {
    pub target_peer_id: String,
    pub session_id: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PeerDisconnectedPayload {
    pub peer_id: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ErrorPayload {
    pub code: u32,
    pub message: String,
}

/// Well-known error codes from the signaling server.
pub mod error_codes {
    pub const PEER_ID_TAKEN: u32 = 1001;
    pub const TARGET_NOT_FOUND: u32 = 1002;
    pub const NOT_REGISTERED: u32 = 1003;
    pub const INVALID_MESSAGE: u32 = 1004;
    pub const SERVER_FULL: u32 = 1005;
    pub const RATE_LIMITED: u32 = 1006;
}

/// Current protocol version.
pub const PROTOCOL_VERSION: u32 = 1;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_register() {
        let msg = SignalingMessage::Register(RegisterPayload {
            peer_id: "alice".to_string(),
            protocol_version: PROTOCOL_VERSION,
        });
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"Register\""));
        assert!(json.contains("\"peer_id\":\"alice\""));
    }

    #[test]
    fn test_roundtrip_candidate() {
        let msg = SignalingMessage::Candidate(CandidatePayload {
            target_peer_id: "bob".to_string(),
            session_id: "session-1".to_string(),
            candidate: IceCandidate {
                candidate_type: CandidateType::ServerReflexive,
                address: "203.0.113.45:32456".to_string(),
                priority: 100,
                protocol: TransportProtocol::Udp,
            },
        });
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: SignalingMessage = serde_json::from_str(&json).unwrap();
        if let SignalingMessage::Candidate(c) = parsed {
            assert_eq!(c.target_peer_id, "bob");
            assert_eq!(c.candidate.candidate_type, CandidateType::ServerReflexive);
        } else {
            panic!("Expected Candidate message");
        }
    }

    #[test]
    fn test_serialize_ping_pong() {
        let ping = serde_json::to_string(&SignalingMessage::Ping).unwrap();
        assert_eq!(ping, "{\"type\":\"Ping\"}");
        let pong = serde_json::to_string(&SignalingMessage::Pong).unwrap();
        assert_eq!(pong, "{\"type\":\"Pong\"}");
    }
}
