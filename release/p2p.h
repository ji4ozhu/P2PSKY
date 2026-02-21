#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <ostream>
#include <new>

/// Connection state reported via callback.
enum class P2pConnectionStateC {
  Connecting = 0,
  Connected = 1,
  Relayed = 2,
  Reconnecting = 3,
  Disconnected = 4,
  Gathering = 5,
  Punching = 6,
};

/// C-compatible error codes.
enum class P2pErrorCode {
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
};

/// Opaque handle to the P2P library instance.
struct P2pHandle {
  uint8_t _private[0];
};

/// Configuration for P2P initialization.
struct P2pConfigC {
  /// WebSocket URL of the signaling server (e.g., "ws://localhost:8080")
  const char *signaling_url;
  /// STUN server address (NULL = use defaults)
  const char *stun_server;
  /// Whether to enable IPv6 dual-stack
  bool enable_ipv6;
  /// KCP mode: 0 = Normal, 1 = Fast, 2 = Turbo
  uint32_t kcp_mode;
};

/// Callback: connection state changed.
using P2pStateCallbackFn = void(*)(const char *peer_id, P2pConnectionStateC state, void *user_data);

/// Callback: data received from a peer.
using P2pReceiveCallbackFn = void(*)(const char *peer_id,
                                     const uint8_t *data,
                                     uint32_t data_len,
                                     void *user_data);

/// Callback: incoming connection request.
/// Return true to accept, false to reject.
using P2pIncomingCallbackFn = bool(*)(const char *peer_id, void *user_data);

/// Full connection statistics snapshot (matches IUdxInfo-style interface).
struct P2pStatsC {
  /// Total bytes received (application level)
  uint64_t bytes_read;
  /// Total bytes sent (application level)
  uint64_t bytes_written;
  /// Total raw UDP packets received
  uint64_t packets_recv;
  /// Total raw UDP packets sent
  uint64_t packets_sent;
  /// Total retransmitted packets
  uint64_t packets_retransmit;
  /// Total FEC parity packets sent
  uint64_t fec_packets_sent;
  /// Total packets recovered by FEC
  uint64_t fec_recoveries;
  /// Current smoothed RTT in milliseconds
  float rtt_ms;
  /// Minimum observed RTT in milliseconds
  float rtt_min_ms;
  /// RTT jitter in microseconds
  uint32_t rtt_var_us;
  /// Current retransmission timeout in milliseconds
  uint32_t rto_ms;
  /// Current packet loss percentage (0.0 - 100.0)
  float loss_percent;
  /// Current receive speed in bytes/sec
  uint64_t speed_recv;
  /// Current send speed in bytes/sec
  uint64_t speed_send;
  /// Current send window size (packets)
  uint32_t send_window;
  /// Current receive window size (packets)
  uint32_t recv_window;
  /// Packets sent but not yet acknowledged
  uint32_t inflight;
  /// Packets in send buffer
  uint32_t send_queue_len;
  /// Packets in receive buffer
  uint32_t recv_queue_len;
  /// Whether currently relayed through TURN
  bool is_relayed;
  /// Whether FEC is enabled
  bool fec_enabled;
  /// Whether encryption is enabled
  bool encryption_enabled;
  /// Whether DNS disguise is enabled
  bool dns_disguise_enabled;
  /// Remote peer address as null-terminated string, e.g. "1.2.3.4:5678"
  uint8_t remote_addr[64];
  /// Local UDP port used for this connection
  uint16_t local_port;
};

extern "C" {

/// Initialize the P2P library.
///
/// Returns an opaque handle that must be passed to all subsequent calls.
/// Returns NULL on failure.
P2pHandle *p2p_init(const P2pConfigC *config);

/// Shut down the library and free all resources.
///
/// After this call, the handle is no longer valid. Any subsequent API calls
/// using this handle will return `NotInitialized`.
/// Calling shutdown twice is safe (returns `NotInitialized` on the second call).
P2pErrorCode p2p_shutdown(P2pHandle *handle);

/// Register this peer with the signaling server.
P2pErrorCode p2p_register(P2pHandle *handle, const char *peer_id);

/// Unregister from the signaling server and clean up all connections.
///
/// This disconnects all peers, stops all background tasks, and destroys the
/// ConnectionManager — but keeps the P2pHandle (and its tokio runtime) alive.
/// After this call, `p2p_register()` can be called again with the same handle.
P2pErrorCode p2p_unregister(P2pHandle *handle);

/// Set or clear TURN server configuration dynamically.
///
/// Can be called at any time after `p2p_register()`. New connections will use
/// the updated TURN config. Existing connections are not affected.
///
/// To enable TURN: pass non-NULL `server`, `username`, and `password`.
/// To disable TURN: pass NULL for `server` (username and password are ignored).
///
/// The strings are copied internally; the caller may free them after this call returns.
P2pErrorCode p2p_set_turn_server(P2pHandle *handle,
                                 const char *server,
                                 const char *username,
                                 const char *password);

/// Set callback for connection state changes.
P2pErrorCode p2p_set_state_callback(P2pHandle *handle,
                                    P2pStateCallbackFn callback,
                                    void *user_data);

/// Set callback for incoming data.
P2pErrorCode p2p_set_receive_callback(P2pHandle *handle,
                                      P2pReceiveCallbackFn callback,
                                      void *user_data);

/// Set callback for incoming connection requests.
P2pErrorCode p2p_set_incoming_callback(P2pHandle *handle,
                                       P2pIncomingCallbackFn callback,
                                       void *user_data);

/// Initiate a connection to a remote peer.
///
/// `punch_timeout_ms`: per-connect hole punch timeout in milliseconds.
///   0 = use the default (15s). If punching doesn't succeed within this time,
///   the connection falls back to TURN relay (if configured).
///
/// `turn_only`: if true, skip hole punching entirely and go straight to TURN relay.
///   Candidate gathering still runs (TURN allocation is needed), but no probes are sent.
P2pErrorCode p2p_connect(P2pHandle *handle,
                         const char *remote_peer_id,
                         uint32_t punch_timeout_ms,
                         bool turn_only);

/// Send data to a connected peer.
P2pErrorCode p2p_send(P2pHandle *handle,
                      const char *remote_peer_id,
                      const uint8_t *data,
                      uint32_t data_len);

/// Disconnect from a specific peer.
///
/// H1: The manager lock is released before calling disconnect() to prevent
/// deadlock if the disconnect triggers a state callback that re-enters FFI.
P2pErrorCode p2p_disconnect(P2pHandle *handle, const char *remote_peer_id);

/// Disconnect all peers but keep the signaling connection alive.
P2pErrorCode p2p_disconnect_all(P2pHandle *handle);

/// Get the list of connected peers.
///
/// Writes '\n'-separated peer IDs into `buf` (null-terminated).
/// `count_out` receives the number of connected/relayed peers.
/// If `buf` is NULL, only the count is returned.
/// Returns `BufferTooSmall` if the buffer is not large enough.
P2pErrorCode p2p_get_peers(P2pHandle *handle, char *buf, uint32_t buf_len, uint32_t *count_out);

/// Get a human-readable error string.
const char *p2p_error_string(P2pErrorCode error);

/// Get full connection statistics for a peer.
///
/// Writes a snapshot of all connection metrics into `stats_out`.
/// The snapshot includes RTT, speed, loss, cumulative totals, window sizes, and feature flags.
P2pErrorCode p2p_get_stats(P2pHandle *handle, const char *remote_peer_id, P2pStatsC *stats_out);

/// Enable or disable Forward Error Correction (FEC) for a peer's connection.
///
/// When enabled, redundant parity packets are sent so the receiver can recover
/// from packet loss without retransmission. The FEC block size adapts automatically
/// based on observed loss rate.
P2pErrorCode p2p_enable_fec(P2pHandle *handle, const char *remote_peer_id, bool enabled);

/// Enable ChaCha20-Poly1305 AEAD encryption for a peer's connection.
///
/// `key` must point to exactly 32 bytes. Each packet will be encrypted with a
/// random nonce (12 bytes) and authenticated tag (16 bytes), adding 28 bytes overhead.
/// Both sides must call this with the same key for communication to work.
P2pErrorCode p2p_enable_encryption(P2pHandle *handle, const char *remote_peer_id);

/// Disable encryption for a peer's connection.
///
/// Subsequent packets will be sent in plaintext. Already in-flight encrypted
/// packets will still be decrypted correctly.
P2pErrorCode p2p_disable_encryption(P2pHandle *handle, const char *remote_peer_id);

/// Enable or disable DNS protocol disguise for a peer's connection.
///
/// When enabled, all packets are wrapped to look like DNS TXT queries,
/// helping bypass firewalls and DPI that block non-standard UDP traffic.
P2pErrorCode p2p_enable_dns_disguise(P2pHandle *handle, const char *remote_peer_id, bool enabled);

/// Enable or disable automatic P2P retry for a peer currently using TURN relay.
///
/// When enabled, the library periodically attempts hole punching (every 5 seconds)
/// while the connection is in Relayed state. If a direct P2P path is found, the
/// session seamlessly switches from TURN relay to direct UDP without interruption.
///
/// This is a per-peer dynamic toggle — can be called at any time after `p2p_connect()`.
/// If called before the connection enters Relayed state, the flag is stored and the
/// retry loop starts automatically once TURN relay is established.
P2pErrorCode p2p_enable_p2p_retry(P2pHandle *handle, const char *remote_peer_id, bool enabled);

}  // extern "C"
