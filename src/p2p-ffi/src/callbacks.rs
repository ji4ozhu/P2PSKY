use std::ffi::{c_char, c_void};

use crate::types::P2pConnectionStateC;

/// Callback: connection state changed.
pub type P2pStateCallbackFn = extern "C" fn(
    peer_id: *const c_char,
    state: P2pConnectionStateC,
    user_data: *mut c_void,
);

/// Callback: data received from a peer.
pub type P2pReceiveCallbackFn = extern "C" fn(
    peer_id: *const c_char,
    data: *const u8,
    data_len: u32,
    user_data: *mut c_void,
);

/// Callback: incoming connection request.
/// Return true to accept, false to reject.
pub type P2pIncomingCallbackFn = extern "C" fn(
    peer_id: *const c_char,
    user_data: *mut c_void,
) -> bool;
