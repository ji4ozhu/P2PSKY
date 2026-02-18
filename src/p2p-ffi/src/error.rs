/// C-compatible error codes.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum P2pErrorCode {
    Ok = 0,
    InvalidArgument = 1,
    NotInitialized = 2,
    AlreadyInitialized = 3,
    SignalingConnectionFailed = 4,
    PeerNotFound = 5,
    ConnectionFailed = 6,
    Timeout = 7,
    SendFailed = 8,
    BufferTooSmall = 9,
    AlreadyConnected = 10,
    NotConnected = 11,
    EncryptionError = 12,
    InternalError = 99,
}
