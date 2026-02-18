use thiserror::Error;

#[derive(Error, Debug)]
pub enum P2pError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("STUN error: {0}")]
    Stun(#[from] p2p_stun::binding::StunError),
    #[error("TURN error: {0}")]
    Turn(#[from] p2p_turn::TurnError),
    #[error("Signaling error: {0}")]
    Signaling(#[from] p2p_signaling_client::SignalingClientError),
    #[error("Connection timed out")]
    Timeout,
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),
    #[error("Not connected")]
    NotConnected,
    #[error("Already connected")]
    AlreadyConnected,
    #[error("Peer not found: {0}")]
    PeerNotFound(String),
    #[error("KCP error: {0}")]
    Kcp(String),
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
}
