use std::io::Write;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use kcp::Kcp;
use parking_lot::Mutex;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::config::KcpMode;
use crate::dual_stack::DualStackSocket;
use crate::pipeline::PacketPipeline;
use crate::stats::ConnectionStats;

/// Output handler for KCP: when KCP wants to send a packet, we queue it.
struct KcpOutput {
    tx: mpsc::UnboundedSender<Vec<u8>>,
}

impl Write for KcpOutput {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        tracing::debug!("KcpOutput: KCP produced {} byte raw packet", buf.len());
        let _ = self.tx.send(buf.to_vec());
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// TURN relay wrapping configuration for a KCP session.
/// When set, all outgoing packets are wrapped in TURN ChannelData format
/// and sent to the TURN server instead of directly to the peer.
#[derive(Debug, Clone)]
struct TurnWrapInfo {
    channel: u16,
    turn_server: SocketAddr,
}

/// A KCP session with multi-threaded IO and integrated packet pipeline.
///
/// Architecture:
/// - **Update task**: Drives KCP's internal timers (retransmission, etc.)
/// - **Send task**: Takes KCP output packets, runs them through the pipeline
///   (FEC -> Encrypt -> DNS disguise), and sends over UDP
/// - **Recv processing**: External code calls `input_wire()` which runs incoming
///   packets through the reverse pipeline
///
/// Supports optional TURN relay wrapping: when enabled via `enable_turn_relay()`,
/// all outgoing packets are wrapped in ChannelData format and sent to the TURN
/// server. The remote peer sends data through the same TURN relay.
pub struct KcpSession {
    kcp: Arc<Mutex<Kcp<KcpOutput>>>,
    remote_addr: Arc<parking_lot::RwLock<SocketAddr>>,
    socket: Arc<DualStackSocket>,
    pipeline: Arc<PacketPipeline>,
    pub stats: Arc<ConnectionStats>,
    turn_wrap: Arc<parking_lot::RwLock<Option<TurnWrapInfo>>>,
    update_handle: Option<JoinHandle<()>>,
    send_handle: Option<JoinHandle<()>>,
    stats_handle: Option<JoinHandle<()>>,
    conv_id: u32,
}

impl KcpSession {
    /// Create a new KCP session over the given socket and remote address.
    pub fn new(
        conv_id: u32,
        remote_addr: SocketAddr,
        socket: Arc<DualStackSocket>,
        mode: KcpMode,
    ) -> Self {
        let stats = Arc::new(ConnectionStats::new());
        let pipeline = Arc::new(PacketPipeline::new(stats.clone()));

        let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let output = KcpOutput { tx };
        let mut kcp = Kcp::new(conv_id, output);

        // Configure KCP based on mode
        match mode {
            KcpMode::Normal => {
                kcp.set_nodelay(false, 40, 0, false);
                kcp.set_wndsize(128, 128);
            }
            KcpMode::Fast => {
                kcp.set_nodelay(true, 10, 2, true);
                kcp.set_wndsize(256, 256);
            }
            KcpMode::Turbo => {
                kcp.set_nodelay(true, 5, 1, true);
                kcp.set_wndsize(512, 512);
            }
        }
        kcp.set_mtu(1400).unwrap();

        let kcp = Arc::new(Mutex::new(kcp));
        let remote_addr = Arc::new(parking_lot::RwLock::new(remote_addr));
        let turn_wrap = Arc::new(parking_lot::RwLock::new(None));

        let mut session = Self {
            kcp,
            remote_addr,
            socket,
            pipeline,
            stats,
            turn_wrap,
            update_handle: None,
            send_handle: None,
            stats_handle: None,
            conv_id,
        };

        session.start_tasks(rx);
        session
    }

    /// Start all background tasks.
    fn start_tasks(&mut self, output_rx: mpsc::UnboundedReceiver<Vec<u8>>) {
        // Task 1: KCP update loop (drives retransmission timers)
        let kcp_for_update = self.kcp.clone();
        self.update_handle = Some(tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(10));
            loop {
                interval.tick().await;
                let now = current_millis();
                let mut kcp = kcp_for_update.lock();
                kcp.update(now).unwrap();
            }
        }));

        // Task 2: Send pipeline (KCP output -> Pipeline -> [TURN wrap] -> UDP)
        // This task owns the receive end of the KCP output channel
        let pipeline = self.pipeline.clone();
        let socket = self.socket.clone();
        let remote_addr = self.remote_addr.clone();
        let turn_wrap = self.turn_wrap.clone();
        self.send_handle = Some(tokio::spawn(async move {
            Self::send_loop(output_rx, pipeline, socket, remote_addr, turn_wrap).await;
        }));

        // Task 3: Periodic stats update (speed calculation)
        let stats_for_update = self.stats.clone();
        self.stats_handle = Some(tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            loop {
                interval.tick().await;
                stats_for_update.update_speed();
            }
        }));
    }

    /// Send loop: processes KCP output through the pipeline and sends to network.
    /// When TURN relay is enabled, wraps packets in ChannelData and sends to TURN server.
    async fn send_loop(
        mut output_rx: mpsc::UnboundedReceiver<Vec<u8>>,
        pipeline: Arc<PacketPipeline>,
        socket: Arc<DualStackSocket>,
        remote_addr: Arc<parking_lot::RwLock<SocketAddr>>,
        turn_wrap: Arc<parking_lot::RwLock<Option<TurnWrapInfo>>>,
    ) {
        let mut pkt_count: u64 = 0;
        let mut consecutive_errors: u32 = 0;
        while let Some(kcp_packet) = output_rx.recv().await {
            // Run through send pipeline: FEC -> Encrypt -> DNS Disguise
            let wire_packets = pipeline.process_outgoing(&kcp_packet);

            // Check if TURN relay is active
            let turn_info = turn_wrap.read().clone();

            for pkt in wire_packets {
                pkt_count += 1;
                let result = if let Some(ref turn) = turn_info {
                    // TURN relay mode: wrap in ChannelData and send to TURN server
                    let channel_data = p2p_turn::allocation::build_channel_data(turn.channel, &pkt);
                    socket.send_to(&channel_data, turn.turn_server).await
                } else {
                    // Direct mode: send to peer
                    let addr = *remote_addr.read();
                    if pkt_count <= 5 || pkt_count % 100 == 0 {
                        tracing::debug!(
                            "SendLoop: #{} sending {} bytes to {} (wire[0..2]={:02x},{:02x})",
                            pkt_count, pkt.len(), addr,
                            pkt.get(0).copied().unwrap_or(0),
                            pkt.get(1).copied().unwrap_or(0),
                        );
                    }
                    socket.send_to(&pkt, addr).await
                };

                match result {
                    Err(e) => {
                        consecutive_errors += 1;
                        // Reduce log spam: log 1st, 10th, then every 100th error
                        if consecutive_errors == 1
                            || consecutive_errors == 10
                            || consecutive_errors.is_multiple_of(100)
                        {
                            tracing::warn!(
                                "UDP send failed (consecutive={}): {}",
                                consecutive_errors, e
                            );
                        }
                    }
                    Ok(_) => {
                        if consecutive_errors > 0 {
                            tracing::info!(
                                "UDP send recovered after {} consecutive errors",
                                consecutive_errors
                            );
                            consecutive_errors = 0;
                        }
                    }
                }
            }
        }
        tracing::warn!("SendLoop: output channel closed, exiting");
    }

    /// Feed an incoming wire packet through the receive pipeline into KCP.
    /// Called from the recv thread when a packet arrives.
    pub fn input_wire(&self, wire_data: &[u8]) -> Result<(), String> {
        // Run through receive pipeline: DNS Unwrap -> Decrypt -> FEC Decode
        let app_packets = self.pipeline.process_incoming(wire_data);

        let mut kcp = self.kcp.lock();
        for pkt in app_packets {
            kcp.input(&pkt)
                .map(|_| ())
                .map_err(|e| format!("KCP input error: {:?}", e))?;
        }
        Ok(())
    }

    /// Run the receive pipeline only (DNS Unwrap -> Decrypt -> FEC Decode)
    /// WITHOUT feeding into KCP. Returns the decoded app-level packets.
    /// Used by the slow path to check conv_id before committing to KCP input.
    pub fn pipeline_decode(&self, wire_data: &[u8]) -> Vec<Vec<u8>> {
        self.pipeline.process_incoming(wire_data)
    }

    /// Feed a raw KCP packet (already processed through pipeline) into KCP.
    pub fn input(&self, data: &[u8]) -> Result<(), String> {
        let mut kcp = self.kcp.lock();
        kcp.input(data)
            .map(|_| ())
            .map_err(|e| format!("KCP input error: {:?}", e))
    }

    /// Send application data through the KCP session (reliable delivery).
    pub fn send(&self, data: &[u8]) -> Result<(), String> {
        let mut kcp = self.kcp.lock();
        kcp.send(data)
            .map(|_| ())
            .map_err(|e| format!("KCP send error: {:?}", e))
    }

    /// Try to receive decoded application data from the KCP session.
    pub fn recv(&self) -> Option<Vec<u8>> {
        let mut kcp = self.kcp.lock();
        let size = match kcp.peeksize() {
            Ok(s) if s > 0 => s as usize,
            _ => return None,
        };
        let mut buf = vec![0u8; size];
        match kcp.recv(&mut buf) {
            Ok(n) => {
                buf.truncate(n);
                Some(buf)
            }
            Err(_) => None,
        }
    }

    /// Get the conversation ID.
    pub fn conv_id(&self) -> u32 {
        self.conv_id
    }

    /// Get the current remote address.
    pub fn remote_addr(&self) -> SocketAddr {
        *self.remote_addr.read()
    }

    /// Switch the remote address (for seamless P2P/TURN switching).
    /// This atomically updates the remote address used by the send loop.
    /// The KCP session continues without interruption.
    pub fn switch_remote(&self, new_addr: SocketAddr) {
        let mut addr = self.remote_addr.write();
        tracing::info!(
            "Switching KCP session {} remote: {} -> {}",
            self.conv_id, *addr, new_addr
        );
        *addr = new_addr;
        // Update relay status in stats
        // (caller should set is_relayed separately based on context)
    }

    /// Get the packet pipeline for runtime configuration.
    pub fn pipeline(&self) -> &Arc<PacketPipeline> {
        &self.pipeline
    }

    /// Enable TURN relay wrapping for this session.
    ///
    /// When enabled, all outgoing packets are wrapped in TURN ChannelData format
    /// and sent to the TURN server. The TURN server forwards them to the peer
    /// via the specified channel binding.
    pub fn enable_turn_relay(&self, channel: u16, turn_server: SocketAddr) {
        tracing::info!(
            "KCP session {} enabling TURN relay: channel=0x{:04X}, server={}",
            self.conv_id, channel, turn_server
        );
        *self.turn_wrap.write() = Some(TurnWrapInfo { channel, turn_server });
    }

    /// Disable TURN relay wrapping, reverting to direct UDP sends.
    pub fn disable_turn_relay(&self) {
        tracing::info!("KCP session {} disabling TURN relay", self.conv_id);
        *self.turn_wrap.write() = None;
    }

    /// Check if TURN relay is currently active.
    pub fn is_turn_relayed(&self) -> bool {
        self.turn_wrap.read().is_some()
    }
}

impl Drop for KcpSession {
    fn drop(&mut self) {
        if let Some(h) = self.update_handle.take() {
            h.abort();
        }
        if let Some(h) = self.send_handle.take() {
            h.abort();
        }
        if let Some(h) = self.stats_handle.take() {
            h.abort();
        }
    }
}

/// Packet type classification for the shared UDP socket demultiplexer.
#[derive(Debug)]
pub enum PacketType {
    /// STUN message (magic cookie 0x2112A442 at bytes 4-7)
    Stun,
    /// Hole punch probe (magic "P2P1" at bytes 0-3)
    PunchProbe,
    /// KCP data packet with the given conv_id
    Kcp { conv_id: u32 },
    /// KCP pipeline packet where conv_id cannot be extracted
    /// (encryption or DNS disguise is active, obscuring the inner data)
    KcpOpaque,
    /// TURN ChannelData (channel number 0x4000-0x7FFF)
    TurnChannelData { channel: u16 },
    /// Unknown packet type
    Unknown,
}

/// Classify an incoming UDP packet to determine its protocol.
///
/// Handles all combinations of pipeline layers (DNS disguise / Crypto / FEC):
/// - DNS=off, Crypto=off: flag bytes `[0x00][0x00]`, conv_id readable
/// - DNS=off, Crypto=on:  flag bytes `[0x00][0x01]`, conv_id encrypted → KcpOpaque
/// - DNS=on:              flag byte  `[0x01]...`,     conv_id buried in DNS → KcpOpaque
pub fn classify_packet(data: &[u8]) -> PacketType {
    if data.len() < 4 {
        return PacketType::Unknown;
    }

    // 1. Hole punch probe (magic "P2P1" = 0x50325031)
    if data.len() >= 17 && data[0..4] == crate::punch::PROBE_MAGIC {
        return PacketType::PunchProbe;
    }

    // 2. TURN ChannelData (channel number 0x4000-0x7FFF)
    let first_two = u16::from_be_bytes([data[0], data[1]]);
    if (0x4000..=0x7FFF).contains(&first_two) {
        return PacketType::TurnChannelData { channel: first_two };
    }

    // 3. STUN (magic cookie at bytes 4-7 + message length validation)
    //    STUN messages: first 2 bits are 0, bytes 4-7 = 0x2112A442,
    //    and msg_length (bytes 2-3) + 20 == total packet length.
    //    The length check reduces false positives from encrypted/random data
    //    whose nonce bytes happen to match the magic cookie.
    if data.len() >= 20 {
        let cookie = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        if cookie == 0x2112A442 {
            let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
            if msg_len + 20 == data.len() {
                return PacketType::Stun;
            }
        }
    }

    // 4. KCP pipeline packets: classify by outer layer flags
    //
    // Wire format: [dns_flag][crypto_flag][fec_flag][...]
    //   dns_flag:    0x00 = off, 0x01 = DNS disguise active
    //   crypto_flag: 0x00 = off, 0x01 = encrypted
    //   fec_flag:    0x00 = off, 0x01 = FEC active
    //
    // We can only extract conv_id when both DNS and Crypto are off,
    // because those layers obscure all subsequent bytes.

    let dns_flag = data[0];

    // DNS disguise active → inner data is encoded as DNS labels, conv_id not readable
    if dns_flag == 0x01 {
        return PacketType::KcpOpaque;
    }

    // DNS off (0x00) → check crypto layer
    if dns_flag == 0x00 && data.len() >= 2 {
        let crypto_flag = data[1];

        // Crypto active → inner data is encrypted, conv_id not readable
        if crypto_flag == 0x01 {
            return PacketType::KcpOpaque;
        }

        // Crypto off (0x00) → check FEC layer, conv_id is readable
        if crypto_flag == 0x00 && data.len() >= 3 {
            let fec_flag = data[2];

            if fec_flag == 0x00 {
                // FEC disabled: [0x00 dns][0x00 crypto][0x00 fec][conv_id_le(4)]...
                // conv_id at byte offset 3
                if data.len() >= 7 {
                    let conv_id = u32::from_le_bytes([data[3], data[4], data[5], data[6]]);
                    return PacketType::Kcp { conv_id };
                }
            } else if fec_flag == 0x01 {
                // FEC enabled: [0x00 dns][0x00 crypto][0x01 fec][group_seq:4][shard_idx:2][shard_size:2][orig_len:2][conv_id_le(4)]...
                // conv_id at byte offset 13 (after 2-byte length prefix embedded by FEC encoder)
                if data.len() >= 17 {
                    let conv_id = u32::from_le_bytes([data[13], data[14], data[15], data[16]]);
                    return PacketType::Kcp { conv_id };
                }
            }
        }
    }

    PacketType::Unknown
}

/// Get monotonic time in milliseconds, suitable for KCP internal clock.
/// Uses Instant (monotonic) instead of SystemTime to avoid issues with
/// NTP corrections causing time to jump backwards.
fn current_millis() -> u32 {
    use std::sync::OnceLock;
    use std::time::Instant;
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    let epoch = EPOCH.get_or_init(Instant::now);
    (epoch.elapsed().as_millis() & 0xFFFFFFFF) as u32
}
