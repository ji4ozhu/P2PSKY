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
  /// TURN server address (NULL = no TURN)
  const char *turn_server;
  /// TURN username (NULL if no TURN)
  const char *turn_username;
  /// TURN password (NULL if no TURN)
  const char *turn_password;
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
P2pErrorCode p2p_connect(P2pHandle *handle, const char *remote_peer_id);

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

}  // extern "C"
