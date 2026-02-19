mod callbacks;
mod error;
mod types;

use std::ffi::{CStr, CString, c_char, c_void};
use std::ptr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use parking_lot::Mutex;
use tokio::runtime::Runtime;

use p2p_core::{ConnectionManager, ConnectionState, P2pConfig};
use p2p_core::config::{KcpMode, TurnConfig};

use crate::callbacks::*;
use crate::error::P2pErrorCode;
use crate::types::*;

/// Internal state behind the opaque P2pHandle.
struct P2pInner {
    /// Whether shutdown has been called. Checked by all API functions.
    shutdown: AtomicBool,
    // M11: manager is declared before runtime so it drops first.
    // Rust drops fields in declaration order. If runtime dropped first,
    // all spawned tasks would be killed before the manager could abort them cleanly.
    manager: Mutex<Option<Arc<ConnectionManager>>>,
    config: P2pConfig,
    state_cb: Mutex<Option<(P2pStateCallbackFn, *mut c_void)>>,
    recv_cb: Mutex<Option<(P2pReceiveCallbackFn, *mut c_void)>>,
    incoming_cb: Mutex<Option<(P2pIncomingCallbackFn, *mut c_void)>>,
    runtime: Runtime,
}

// Safety: The callback user_data pointers are managed by the caller.
unsafe impl Send for P2pInner {}
unsafe impl Sync for P2pInner {}

/// Initialize the P2P library.
///
/// Returns an opaque handle that must be passed to all subsequent calls.
/// Returns NULL on failure.
#[no_mangle]
pub extern "C" fn p2p_init(config: *const P2pConfigC) -> *mut P2pHandle {
    if config.is_null() {
        return ptr::null_mut();
    }

    // Initialize tracing subscriber for P2P process logging.
    // Uses RUST_LOG env var for filtering; defaults to info level for p2p crates.
    use std::sync::Once;
    static TRACING_INIT: Once = Once::new();
    TRACING_INIT.call_once(|| {
        use tracing_subscriber::EnvFilter;
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
            EnvFilter::new("p2p_core=info,p2p_stun=info,p2p_turn=info,p2p_signaling_client=info,p2p_ffi=info")
        });
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(true)
            .with_thread_ids(false)
            .with_file(false)
            .with_line_number(false)
            .init();
    });

    let config_c = unsafe { &*config };

    let rust_config = match convert_config(config_c) {
        Some(c) => c,
        None => return ptr::null_mut(),
    };

    let runtime = match Runtime::new() {
        Ok(r) => r,
        Err(_) => return ptr::null_mut(),
    };

    let inner = Box::new(P2pInner {
        shutdown: AtomicBool::new(false),
        manager: Mutex::new(None),
        config: rust_config,
        state_cb: Mutex::new(None),
        recv_cb: Mutex::new(None),
        incoming_cb: Mutex::new(None),
        runtime,
    });

    Box::into_raw(inner) as *mut P2pHandle
}

/// Shut down the library and free all resources.
///
/// After this call, the handle is no longer valid. Any subsequent API calls
/// using this handle will return `NotInitialized`.
/// Calling shutdown twice is safe (returns `NotInitialized` on the second call).
#[no_mangle]
pub extern "C" fn p2p_shutdown(handle: *mut P2pHandle) -> P2pErrorCode {
    if handle.is_null() {
        return P2pErrorCode::InvalidArgument;
    }

    // Safety: we only dereference the pointer to set the shutdown flag.
    // The AtomicBool swap ensures only one caller proceeds to drop.
    let inner = unsafe { &*(handle as *const P2pInner) };

    // Atomically set shutdown=true. If it was already true, another thread
    // (or a prior call) already owns the drop — return early.
    if inner.shutdown.swap(true, Ordering::AcqRel) {
        return P2pErrorCode::NotInitialized;
    }

    // We are the sole owner now. Shut down the manager first (abort tasks)
    // before dropping the runtime. This ensures clean task cancellation.
    {
        let inner = unsafe { &*(handle as *const P2pInner) };
        let manager = inner.manager.lock().take();
        if let Some(m) = manager {
            m.shutdown();
        }
    }

    // Reconstruct the Box and drop it (drops runtime last).
    let inner = unsafe { Box::from_raw(handle as *mut P2pInner) };
    drop(inner);
    P2pErrorCode::Ok
}

/// Register this peer with the signaling server.
#[no_mangle]
pub extern "C" fn p2p_register(handle: *mut P2pHandle, peer_id: *const c_char) -> P2pErrorCode {
    let inner = match get_inner(handle) {
        Some(i) => i,
        None => return P2pErrorCode::NotInitialized,
    };

    let peer_id = match unsafe_cstr_to_string(peer_id) {
        Some(s) => s,
        None => return P2pErrorCode::InvalidArgument,
    };

    // Create the connection manager and register
    let config = inner.config.clone();
    let result = inner.runtime.block_on(async {
        let manager = ConnectionManager::new(config).await?;
        manager.register(&peer_id).await?;
        Ok::<Arc<ConnectionManager>, p2p_core::P2pError>(manager)
    });

    match result {
        Ok(manager) => {
            // Bridge Rust callbacks to C callbacks.
            // Safety: `inner_addr` holds the address of P2pInner, valid for the
            // lifetime of the P2pHandle. Stored as usize to satisfy Send+Sync.
            let inner_addr = handle as usize;

            // State callback bridge
            manager.set_state_callback(Box::new(move |peer_id, state| {
                let inner = unsafe { &*(inner_addr as *const P2pInner) };
                let guard = inner.state_cb.lock();
                if let Some((cb, user_data)) = guard.as_ref() {
                    let c_state = match state {
                        ConnectionState::Gathering => P2pConnectionStateC::Gathering,
                        ConnectionState::Punching => P2pConnectionStateC::Punching,
                        ConnectionState::KcpHandshake => P2pConnectionStateC::Connecting,
                        ConnectionState::Connected => P2pConnectionStateC::Connected,
                        ConnectionState::Relayed => P2pConnectionStateC::Relayed,
                        ConnectionState::Reconnecting => P2pConnectionStateC::Reconnecting,
                        ConnectionState::Disconnected => P2pConnectionStateC::Disconnected,
                        _ => P2pConnectionStateC::Connecting,
                    };
                    if let Ok(c_peer_id) = CString::new(peer_id) {
                        cb(c_peer_id.as_ptr(), c_state, *user_data);
                    }
                }
            }));

            // Receive callback bridge
            manager.set_receive_callback(Box::new(move |peer_id, data| {
                let inner = unsafe { &*(inner_addr as *const P2pInner) };
                let guard = inner.recv_cb.lock();
                if let Some((cb, user_data)) = guard.as_ref() {
                    if let Ok(c_peer_id) = CString::new(peer_id) {
                        cb(c_peer_id.as_ptr(), data.as_ptr(), data.len() as u32, *user_data);
                    }
                }
            }));

            // Incoming connection callback bridge
            manager.set_incoming_callback(Box::new(move |peer_id| {
                let inner = unsafe { &*(inner_addr as *const P2pInner) };
                let guard = inner.incoming_cb.lock();
                if let Some((cb, user_data)) = guard.as_ref() {
                    if let Ok(c_peer_id) = CString::new(peer_id) {
                        return cb(c_peer_id.as_ptr(), *user_data);
                    }
                }
                true // accept by default if no callback set
            }));

            // C5: Check if a manager already exists — refuse to overwrite
            // to prevent leaking the old manager's background tasks.
            {
                let mut guard = inner.manager.lock();
                if guard.is_some() {
                    tracing::error!("p2p_register called but a manager is already registered");
                    return P2pErrorCode::AlreadyInitialized;
                }
                *guard = Some(manager);
            }
            P2pErrorCode::Ok
        }
        Err(e) => {
            tracing::error!("Registration failed: {}", e);
            P2pErrorCode::SignalingConnectionFailed
        }
    }
}

/// Set or clear TURN server configuration dynamically.
///
/// Can be called at any time after `p2p_register()`. New connections will use
/// the updated TURN config. Existing connections are not affected.
///
/// To enable TURN: pass non-NULL `server`, `username`, and `password`.
/// To disable TURN: pass NULL for `server` (username and password are ignored).
///
/// The strings are copied internally; the caller may free them after this call returns.
#[no_mangle]
pub extern "C" fn p2p_set_turn_server(
    handle: *mut P2pHandle,
    server: *const c_char,
    username: *const c_char,
    password: *const c_char,
) -> P2pErrorCode {
    let inner = match get_inner(handle) {
        Some(i) => i,
        None => return P2pErrorCode::NotInitialized,
    };

    let turn_config = if server.is_null() {
        None
    } else {
        let server_addr = match unsafe_cstr_to_string(server) {
            Some(s) => s,
            None => return P2pErrorCode::InvalidArgument,
        };
        let user = match unsafe_cstr_to_string(username) {
            Some(s) => s,
            None => return P2pErrorCode::InvalidArgument,
        };
        let pass = match unsafe_cstr_to_string(password) {
            Some(s) => s,
            None => return P2pErrorCode::InvalidArgument,
        };
        Some(TurnConfig {
            server_addr,
            username: user,
            password: pass,
        })
    };

    let manager = {
        let guard = inner.manager.lock();
        match guard.as_ref() {
            Some(m) => m.clone(),
            None => return P2pErrorCode::NotInitialized,
        }
    };

    manager.set_turn_config(turn_config);
    P2pErrorCode::Ok
}

/// Set callback for connection state changes.
#[no_mangle]
pub extern "C" fn p2p_set_state_callback(
    handle: *mut P2pHandle,
    callback: P2pStateCallbackFn,
    user_data: *mut c_void,
) -> P2pErrorCode {
    let inner = match get_inner(handle) {
        Some(i) => i,
        None => return P2pErrorCode::NotInitialized,
    };
    *inner.state_cb.lock() = Some((callback, user_data));
    P2pErrorCode::Ok
}

/// Set callback for incoming data.
#[no_mangle]
pub extern "C" fn p2p_set_receive_callback(
    handle: *mut P2pHandle,
    callback: P2pReceiveCallbackFn,
    user_data: *mut c_void,
) -> P2pErrorCode {
    let inner = match get_inner(handle) {
        Some(i) => i,
        None => return P2pErrorCode::NotInitialized,
    };
    *inner.recv_cb.lock() = Some((callback, user_data));
    P2pErrorCode::Ok
}

/// Set callback for incoming connection requests.
#[no_mangle]
pub extern "C" fn p2p_set_incoming_callback(
    handle: *mut P2pHandle,
    callback: P2pIncomingCallbackFn,
    user_data: *mut c_void,
) -> P2pErrorCode {
    let inner = match get_inner(handle) {
        Some(i) => i,
        None => return P2pErrorCode::NotInitialized,
    };
    *inner.incoming_cb.lock() = Some((callback, user_data));
    P2pErrorCode::Ok
}

/// Initiate a connection to a remote peer.
///
/// `punch_timeout_ms`: per-connect hole punch timeout in milliseconds.
///   0 = use the default (15s). If punching doesn't succeed within this time,
///   the connection falls back to TURN relay (if configured).
///
/// `turn_only`: if true, skip hole punching entirely and go straight to TURN relay.
///   Candidate gathering still runs (TURN allocation is needed), but no probes are sent.
#[no_mangle]
pub extern "C" fn p2p_connect(
    handle: *mut P2pHandle,
    remote_peer_id: *const c_char,
    punch_timeout_ms: u32,
    turn_only: bool,
) -> P2pErrorCode {
    let inner = match get_inner(handle) {
        Some(i) => i,
        None => return P2pErrorCode::NotInitialized,
    };

    let remote_id = match unsafe_cstr_to_string(remote_peer_id) {
        Some(s) => s,
        None => return P2pErrorCode::InvalidArgument,
    };

    let punch_timeout = if punch_timeout_ms == 0 {
        None
    } else {
        Some(std::time::Duration::from_millis(punch_timeout_ms as u64))
    };

    let manager_lock = inner.manager.lock();
    let manager = match manager_lock.as_ref() {
        Some(m) => m.clone(),
        None => return P2pErrorCode::NotInitialized,
    };
    drop(manager_lock);

    let result = inner.runtime.block_on(async {
        manager.connect(&remote_id, punch_timeout, turn_only).await
    });

    match result {
        Ok(()) => P2pErrorCode::Ok,
        Err(e) => {
            tracing::error!("Connect failed: {}", e);
            P2pErrorCode::ConnectionFailed
        }
    }
}

/// Send data to a connected peer.
#[no_mangle]
pub extern "C" fn p2p_send(
    handle: *mut P2pHandle,
    remote_peer_id: *const c_char,
    data: *const u8,
    data_len: u32,
) -> P2pErrorCode {
    let inner = match get_inner(handle) {
        Some(i) => i,
        None => return P2pErrorCode::NotInitialized,
    };

    let remote_id = match unsafe_cstr_to_string(remote_peer_id) {
        Some(s) => s,
        None => return P2pErrorCode::InvalidArgument,
    };

    if data.is_null() || data_len == 0 {
        return P2pErrorCode::InvalidArgument;
    }

    let buf = unsafe { std::slice::from_raw_parts(data, data_len as usize) };

    let manager = {
        let guard = inner.manager.lock();
        match guard.as_ref() {
            Some(m) => m.clone(),
            None => return P2pErrorCode::NotInitialized,
        }
    };
    // Lock is dropped — safe to call methods that may trigger callbacks.

    match manager.send(&remote_id, buf) {
        Ok(()) => P2pErrorCode::Ok,
        Err(e) => {
            tracing::error!("Send failed: {}", e);
            P2pErrorCode::SendFailed
        }
    }
}

/// Disconnect from a specific peer.
///
/// H1: The manager lock is released before calling disconnect() to prevent
/// deadlock if the disconnect triggers a state callback that re-enters FFI.
#[no_mangle]
pub extern "C" fn p2p_disconnect(
    handle: *mut P2pHandle,
    remote_peer_id: *const c_char,
) -> P2pErrorCode {
    let inner = match get_inner(handle) {
        Some(i) => i,
        None => return P2pErrorCode::NotInitialized,
    };

    let remote_id = match unsafe_cstr_to_string(remote_peer_id) {
        Some(s) => s,
        None => return P2pErrorCode::InvalidArgument,
    };

    let manager = {
        let guard = inner.manager.lock();
        match guard.as_ref() {
            Some(m) => m.clone(),
            None => return P2pErrorCode::NotInitialized,
        }
    };
    // Lock is dropped here — safe to call methods that may trigger callbacks.
    manager.disconnect(&remote_id);

    P2pErrorCode::Ok
}

/// Get a human-readable error string.
#[no_mangle]
pub extern "C" fn p2p_error_string(error: P2pErrorCode) -> *const c_char {
    let msg = match error {
        P2pErrorCode::Ok => "OK\0",
        P2pErrorCode::InvalidArgument => "Invalid argument\0",
        P2pErrorCode::NotInitialized => "Not initialized\0",
        P2pErrorCode::AlreadyInitialized => "Already initialized\0",
        P2pErrorCode::SignalingConnectionFailed => "Signaling connection failed\0",
        P2pErrorCode::PeerNotFound => "Peer not found\0",
        P2pErrorCode::ConnectionFailed => "Connection failed\0",
        P2pErrorCode::Timeout => "Timeout\0",
        P2pErrorCode::SendFailed => "Send failed\0",
        P2pErrorCode::BufferTooSmall => "Buffer too small\0",
        P2pErrorCode::AlreadyConnected => "Already connected\0",
        P2pErrorCode::NotConnected => "Not connected\0",
        P2pErrorCode::EncryptionError => "Encryption error\0",
        P2pErrorCode::InternalError => "Internal error\0",
    };
    msg.as_ptr() as *const c_char
}

// === Statistics API ===

/// Get full connection statistics for a peer.
///
/// Writes a snapshot of all connection metrics into `stats_out`.
/// The snapshot includes RTT, speed, loss, cumulative totals, window sizes, and feature flags.
#[no_mangle]
pub extern "C" fn p2p_get_stats(
    handle: *mut P2pHandle,
    remote_peer_id: *const c_char,
    stats_out: *mut P2pStatsC,
) -> P2pErrorCode {
    let inner = match get_inner(handle) {
        Some(i) => i,
        None => return P2pErrorCode::NotInitialized,
    };

    let remote_id = match unsafe_cstr_to_string(remote_peer_id) {
        Some(s) => s,
        None => return P2pErrorCode::InvalidArgument,
    };

    if stats_out.is_null() {
        return P2pErrorCode::InvalidArgument;
    }

    let manager = {
        let guard = inner.manager.lock();
        match guard.as_ref() {
            Some(m) => m.clone(),
            None => return P2pErrorCode::NotInitialized,
        }
    };

    match manager.get_stats(&remote_id) {
        Ok(snap) => {
            // Copy remote_addr string into fixed-size buffer
            let mut remote_addr_buf = [0u8; 64];
            let addr_bytes = snap.remote_addr.as_bytes();
            let copy_len = addr_bytes.len().min(63);
            remote_addr_buf[..copy_len].copy_from_slice(&addr_bytes[..copy_len]);

            unsafe {
                *stats_out = P2pStatsC {
                    bytes_read: snap.bytes_read,
                    bytes_written: snap.bytes_written,
                    packets_recv: snap.packets_recv,
                    packets_sent: snap.packets_sent,
                    packets_retransmit: snap.packets_retransmit,
                    fec_packets_sent: snap.fec_packets_sent,
                    fec_recoveries: snap.fec_recoveries,
                    rtt_ms: snap.rtt_ms,
                    rtt_min_ms: snap.rtt_min_ms,
                    rtt_var_us: snap.rtt_var_us,
                    rto_ms: snap.rto_ms,
                    loss_percent: snap.loss_percent,
                    speed_recv: snap.speed_recv,
                    speed_send: snap.speed_send,
                    send_window: snap.send_window,
                    recv_window: snap.recv_window,
                    inflight: snap.inflight,
                    send_queue_len: snap.send_queue_len,
                    recv_queue_len: snap.recv_queue_len,
                    is_relayed: snap.is_relayed,
                    fec_enabled: snap.fec_enabled,
                    encryption_enabled: snap.encryption_enabled,
                    dns_disguise_enabled: snap.dns_disguise_enabled,
                    remote_addr: remote_addr_buf,
                    local_port: snap.local_port,
                };
            }
            P2pErrorCode::Ok
        }
        Err(_) => P2pErrorCode::NotConnected,
    }
}

// === FEC Control API ===

/// Enable or disable Forward Error Correction (FEC) for a peer's connection.
///
/// When enabled, redundant parity packets are sent so the receiver can recover
/// from packet loss without retransmission. The FEC block size adapts automatically
/// based on observed loss rate.
#[no_mangle]
pub extern "C" fn p2p_enable_fec(
    handle: *mut P2pHandle,
    remote_peer_id: *const c_char,
    enabled: bool,
) -> P2pErrorCode {
    let inner = match get_inner(handle) {
        Some(i) => i,
        None => return P2pErrorCode::NotInitialized,
    };

    let remote_id = match unsafe_cstr_to_string(remote_peer_id) {
        Some(s) => s,
        None => return P2pErrorCode::InvalidArgument,
    };

    let manager = {
        let guard = inner.manager.lock();
        match guard.as_ref() {
            Some(m) => m.clone(),
            None => return P2pErrorCode::NotInitialized,
        }
    };

    match manager.enable_fec(&remote_id, enabled) {
        Ok(()) => P2pErrorCode::Ok,
        Err(_) => P2pErrorCode::NotConnected,
    }
}

// === Encryption Control API ===

/// Enable ChaCha20-Poly1305 AEAD encryption for a peer's connection.
///
/// `key` must point to exactly 32 bytes. Each packet will be encrypted with a
/// random nonce (12 bytes) and authenticated tag (16 bytes), adding 28 bytes overhead.
/// Both sides must call this with the same key for communication to work.
#[no_mangle]
pub extern "C" fn p2p_enable_encryption(
    handle: *mut P2pHandle,
    remote_peer_id: *const c_char,
) -> P2pErrorCode {
    let inner = match get_inner(handle) {
        Some(i) => i,
        None => return P2pErrorCode::NotInitialized,
    };

    let remote_id = match unsafe_cstr_to_string(remote_peer_id) {
        Some(s) => s,
        None => return P2pErrorCode::InvalidArgument,
    };

    let manager = {
        let guard = inner.manager.lock();
        match guard.as_ref() {
            Some(m) => m.clone(),
            None => return P2pErrorCode::NotInitialized,
        }
    };

    match manager.enable_encryption(&remote_id) {
        Ok(()) => P2pErrorCode::Ok,
        Err(_) => P2pErrorCode::NotConnected,
    }
}

/// Disable encryption for a peer's connection.
///
/// Subsequent packets will be sent in plaintext. Already in-flight encrypted
/// packets will still be decrypted correctly.
#[no_mangle]
pub extern "C" fn p2p_disable_encryption(
    handle: *mut P2pHandle,
    remote_peer_id: *const c_char,
) -> P2pErrorCode {
    let inner = match get_inner(handle) {
        Some(i) => i,
        None => return P2pErrorCode::NotInitialized,
    };

    let remote_id = match unsafe_cstr_to_string(remote_peer_id) {
        Some(s) => s,
        None => return P2pErrorCode::InvalidArgument,
    };

    let manager = {
        let guard = inner.manager.lock();
        match guard.as_ref() {
            Some(m) => m.clone(),
            None => return P2pErrorCode::NotInitialized,
        }
    };

    match manager.disable_encryption(&remote_id) {
        Ok(()) => P2pErrorCode::Ok,
        Err(_) => P2pErrorCode::NotConnected,
    }
}

// === DNS Disguise Control API ===

/// Enable or disable DNS protocol disguise for a peer's connection.
///
/// When enabled, all packets are wrapped to look like DNS TXT queries,
/// helping bypass firewalls and DPI that block non-standard UDP traffic.
#[no_mangle]
pub extern "C" fn p2p_enable_dns_disguise(
    handle: *mut P2pHandle,
    remote_peer_id: *const c_char,
    enabled: bool,
) -> P2pErrorCode {
    let inner = match get_inner(handle) {
        Some(i) => i,
        None => return P2pErrorCode::NotInitialized,
    };

    let remote_id = match unsafe_cstr_to_string(remote_peer_id) {
        Some(s) => s,
        None => return P2pErrorCode::InvalidArgument,
    };

    let manager = {
        let guard = inner.manager.lock();
        match guard.as_ref() {
            Some(m) => m.clone(),
            None => return P2pErrorCode::NotInitialized,
        }
    };

    match manager.enable_dns_disguise(&remote_id, enabled) {
        Ok(()) => P2pErrorCode::Ok,
        Err(_) => P2pErrorCode::NotConnected,
    }
}

// === P2P Retry Control API ===

/// Enable or disable automatic P2P retry for a peer currently using TURN relay.
///
/// When enabled, the library periodically attempts hole punching (every 5 seconds)
/// while the connection is in Relayed state. If a direct P2P path is found, the
/// session seamlessly switches from TURN relay to direct UDP without interruption.
///
/// This is a per-peer dynamic toggle — can be called at any time after `p2p_connect()`.
/// If called before the connection enters Relayed state, the flag is stored and the
/// retry loop starts automatically once TURN relay is established.
#[no_mangle]
pub extern "C" fn p2p_enable_p2p_retry(
    handle: *mut P2pHandle,
    remote_peer_id: *const c_char,
    enabled: bool,
) -> P2pErrorCode {
    let inner = match get_inner(handle) {
        Some(i) => i,
        None => return P2pErrorCode::NotInitialized,
    };

    let remote_id = match unsafe_cstr_to_string(remote_peer_id) {
        Some(s) => s,
        None => return P2pErrorCode::InvalidArgument,
    };

    let manager = {
        let guard = inner.manager.lock();
        match guard.as_ref() {
            Some(m) => m.clone(),
            None => return P2pErrorCode::NotInitialized,
        }
    };

    match manager.enable_p2p_retry(&remote_id, enabled) {
        Ok(()) => P2pErrorCode::Ok,
        Err(_) => P2pErrorCode::NotConnected,
    }
}

// === Internal helpers ===

fn get_inner(handle: *mut P2pHandle) -> Option<&'static P2pInner> {
    if handle.is_null() {
        return None;
    }
    let inner = unsafe { &*(handle as *const P2pInner) };
    // If shutdown has been called, refuse all further operations.
    if inner.shutdown.load(Ordering::Acquire) {
        return None;
    }
    Some(inner)
}

fn unsafe_cstr_to_string(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(ptr).to_str().ok().map(|s| s.to_string()) }
}

fn convert_config(c: &P2pConfigC) -> Option<P2pConfig> {
    let signaling_url = unsafe_cstr_to_string(c.signaling_url)?;

    let stun_servers = if c.stun_server.is_null() {
        vec![
            "stun.cloudflare.com:3478".to_string(),
            "stun.l.google.com:19302".to_string(),
            "stun.voip.blackberry.com:3478".to_string(),
            "stun.sipnet.com:3478".to_string(),
            "stun.f.haeder.net:3478".to_string(),
        ]
    } else {
        vec![unsafe_cstr_to_string(c.stun_server)?]
    };

    let kcp_mode = match c.kcp_mode {
        0 => KcpMode::Normal,
        1 => KcpMode::Fast,
        2 => KcpMode::Turbo,
        _ => KcpMode::Fast,
    };

    Some(P2pConfig {
        signaling_url,
        stun_servers,
        enable_ipv6: c.enable_ipv6,
        kcp_mode,
        ..Default::default()
    })
}
