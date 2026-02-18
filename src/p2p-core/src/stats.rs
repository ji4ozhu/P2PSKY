use std::sync::atomic::Ordering::Relaxed;
use std::time::Instant;

use portable_atomic::{AtomicU32, AtomicU64};

/// Lock-free connection statistics, updated atomically by send/recv IO threads.
///
/// Modeled after IUdxInfo — provides real-time RTT, speed, loss, cumulative
/// data totals, window info, and more. All fields are atomic for concurrent
/// read/write from multiple threads without locking.
pub struct ConnectionStats {
    // --- Cumulative byte counters ---
    /// Total bytes received (application-level, after KCP reassembly)
    pub bytes_read: AtomicU64,
    /// Total bytes sent (application-level, before KCP segmentation)
    pub bytes_written: AtomicU64,

    // --- Cumulative packet counters ---
    /// Total UDP packets received (raw)
    pub packets_recv: AtomicU64,
    /// Total UDP packets sent (raw)
    pub packets_sent: AtomicU64,
    /// Total retransmitted packets
    pub packets_retransmit: AtomicU64,
    /// Total FEC recovery packets sent
    pub fec_packets_sent: AtomicU64,
    /// Total FEC recoveries performed (packets recovered without retransmit)
    pub fec_recoveries: AtomicU64,

    // --- Real-time metrics ---
    /// Current RTT in microseconds (smoothed)
    pub rtt_us: AtomicU32,
    /// Minimum RTT observed in microseconds
    pub rtt_min_us: AtomicU32,
    /// RTT variance (jitter) in microseconds
    pub rtt_var_us: AtomicU32,
    /// Current RTO (retransmission timeout) in milliseconds
    pub rto_ms: AtomicU32,
    /// Current packet loss ratio (0.0 - 1.0), scaled to 0..10000 for atomic
    pub loss_rate_permyriad: AtomicU32,

    // --- Speed tracking (updated periodically) ---
    /// Current receive speed in bytes/sec
    pub speed_recv: AtomicU64,
    /// Current send speed in bytes/sec
    pub speed_send: AtomicU64,

    // --- Window / buffer state ---
    /// Current send window size
    pub send_window: AtomicU32,
    /// Current receive window size
    pub recv_window: AtomicU32,
    /// Packets sent but not yet acknowledged
    pub inflight: AtomicU32,
    /// Packets waiting in send buffer
    pub send_queue_len: AtomicU32,
    /// Packets waiting in receive buffer
    pub recv_queue_len: AtomicU32,

    // --- Connection metadata ---
    /// Whether currently relayed through TURN
    pub is_relayed: portable_atomic::AtomicBool,
    /// Whether FEC is enabled
    pub fec_enabled: portable_atomic::AtomicBool,
    /// Whether encryption is enabled
    pub encryption_enabled: portable_atomic::AtomicBool,
    /// Whether DNS disguise is enabled
    pub dns_disguise_enabled: portable_atomic::AtomicBool,

    // --- Internal speed calculation state ---
    speed_calc: parking_lot::Mutex<SpeedCalcState>,
}

struct SpeedCalcState {
    last_update: Instant,
    last_bytes_read: u64,
    last_bytes_written: u64,
}

impl ConnectionStats {
    pub fn new() -> Self {
        Self {
            bytes_read: AtomicU64::new(0),
            bytes_written: AtomicU64::new(0),
            packets_recv: AtomicU64::new(0),
            packets_sent: AtomicU64::new(0),
            packets_retransmit: AtomicU64::new(0),
            fec_packets_sent: AtomicU64::new(0),
            fec_recoveries: AtomicU64::new(0),
            rtt_us: AtomicU32::new(0),
            rtt_min_us: AtomicU32::new(u32::MAX),
            rtt_var_us: AtomicU32::new(0),
            rto_ms: AtomicU32::new(200),
            loss_rate_permyriad: AtomicU32::new(0),
            speed_recv: AtomicU64::new(0),
            speed_send: AtomicU64::new(0),
            send_window: AtomicU32::new(0),
            recv_window: AtomicU32::new(0),
            inflight: AtomicU32::new(0),
            send_queue_len: AtomicU32::new(0),
            recv_queue_len: AtomicU32::new(0),
            is_relayed: portable_atomic::AtomicBool::new(false),
            fec_enabled: portable_atomic::AtomicBool::new(false),
            encryption_enabled: portable_atomic::AtomicBool::new(false),
            dns_disguise_enabled: portable_atomic::AtomicBool::new(false),
            speed_calc: parking_lot::Mutex::new(SpeedCalcState {
                last_update: Instant::now(),
                last_bytes_read: 0,
                last_bytes_written: 0,
            }),
        }
    }

    // --- Recording methods (called from IO threads) ---

    pub fn record_bytes_read(&self, n: u64) {
        self.bytes_read.fetch_add(n, Relaxed);
    }

    pub fn record_bytes_written(&self, n: u64) {
        self.bytes_written.fetch_add(n, Relaxed);
    }

    pub fn record_packet_sent(&self) {
        self.packets_sent.fetch_add(1, Relaxed);
    }

    pub fn record_packet_recv(&self) {
        self.packets_recv.fetch_add(1, Relaxed);
    }

    pub fn record_retransmit(&self) {
        self.packets_retransmit.fetch_add(1, Relaxed);
    }

    pub fn record_fec_sent(&self) {
        self.fec_packets_sent.fetch_add(1, Relaxed);
    }

    pub fn record_fec_recovery(&self) {
        self.fec_recoveries.fetch_add(1, Relaxed);
    }

    pub fn update_rtt(&self, rtt_us: u32) {
        self.rtt_us.store(rtt_us, Relaxed);
        // Update minimum RTT
        let mut current_min = self.rtt_min_us.load(Relaxed);
        while rtt_us < current_min {
            match self.rtt_min_us.compare_exchange_weak(current_min, rtt_us, Relaxed, Relaxed) {
                Ok(_) => break,
                Err(actual) => current_min = actual,
            }
        }
    }

    pub fn update_loss_rate(&self, loss_ratio: f32) {
        let permyriad = (loss_ratio.clamp(0.0, 1.0) * 10000.0) as u32;
        self.loss_rate_permyriad.store(permyriad, Relaxed);
    }

    /// Update speed calculations. Should be called periodically (~1 second).
    pub fn update_speed(&self) {
        let mut state = self.speed_calc.lock();
        let now = Instant::now();
        let elapsed = now.duration_since(state.last_update).as_secs_f64();
        if elapsed < 0.1 {
            return; // Too soon
        }

        let current_read = self.bytes_read.load(Relaxed);
        let current_written = self.bytes_written.load(Relaxed);

        let read_delta = current_read.saturating_sub(state.last_bytes_read);
        let write_delta = current_written.saturating_sub(state.last_bytes_written);

        self.speed_recv.store((read_delta as f64 / elapsed) as u64, Relaxed);
        self.speed_send.store((write_delta as f64 / elapsed) as u64, Relaxed);

        state.last_bytes_read = current_read;
        state.last_bytes_written = current_written;
        state.last_update = now;
    }

    // --- Query methods (called from any thread) ---

    /// Get RTT in milliseconds.
    pub fn rtt_ms(&self) -> f32 {
        self.rtt_us.load(Relaxed) as f32 / 1000.0
    }

    /// Get minimum RTT in milliseconds.
    pub fn rtt_min_ms(&self) -> f32 {
        let v = self.rtt_min_us.load(Relaxed);
        if v == u32::MAX { 0.0 } else { v as f32 / 1000.0 }
    }

    /// Get loss rate as a percentage (0.0 - 100.0).
    pub fn loss_percent(&self) -> f32 {
        self.loss_rate_permyriad.load(Relaxed) as f32 / 100.0
    }

    /// Get current receive speed in bytes/sec.
    pub fn current_speed_recv(&self) -> u64 {
        self.speed_recv.load(Relaxed)
    }

    /// Get current send speed in bytes/sec.
    pub fn current_speed_send(&self) -> u64 {
        self.speed_send.load(Relaxed)
    }

    /// Get total bytes received.
    pub fn total_bytes_read(&self) -> u64 {
        self.bytes_read.load(Relaxed)
    }

    /// Get total bytes sent.
    pub fn total_bytes_written(&self) -> u64 {
        self.bytes_written.load(Relaxed)
    }

    /// Take a snapshot of all stats for the C API.
    pub fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            bytes_read: self.bytes_read.load(Relaxed),
            bytes_written: self.bytes_written.load(Relaxed),
            packets_recv: self.packets_recv.load(Relaxed),
            packets_sent: self.packets_sent.load(Relaxed),
            packets_retransmit: self.packets_retransmit.load(Relaxed),
            fec_packets_sent: self.fec_packets_sent.load(Relaxed),
            fec_recoveries: self.fec_recoveries.load(Relaxed),
            rtt_ms: self.rtt_ms(),
            rtt_min_ms: self.rtt_min_ms(),
            rtt_var_us: self.rtt_var_us.load(Relaxed),
            rto_ms: self.rto_ms.load(Relaxed),
            loss_percent: self.loss_percent(),
            speed_recv: self.speed_recv.load(Relaxed),
            speed_send: self.speed_send.load(Relaxed),
            send_window: self.send_window.load(Relaxed),
            recv_window: self.recv_window.load(Relaxed),
            inflight: self.inflight.load(Relaxed),
            send_queue_len: self.send_queue_len.load(Relaxed),
            recv_queue_len: self.recv_queue_len.load(Relaxed),
            is_relayed: self.is_relayed.load(Relaxed),
            fec_enabled: self.fec_enabled.load(Relaxed),
            encryption_enabled: self.encryption_enabled.load(Relaxed),
            dns_disguise_enabled: self.dns_disguise_enabled.load(Relaxed),
            remote_addr: String::new(),
            local_port: 0,
        }
    }
}

impl Default for ConnectionStats {
    fn default() -> Self {
        Self::new()
    }
}

/// A point-in-time snapshot of all connection statistics.
/// Safe to pass across FFI boundary.
#[derive(Debug, Clone)]
pub struct StatsSnapshot {
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub packets_recv: u64,
    pub packets_sent: u64,
    pub packets_retransmit: u64,
    pub fec_packets_sent: u64,
    pub fec_recoveries: u64,
    pub rtt_ms: f32,
    pub rtt_min_ms: f32,
    pub rtt_var_us: u32,
    pub rto_ms: u32,
    pub loss_percent: f32,
    pub speed_recv: u64,
    pub speed_send: u64,
    pub send_window: u32,
    pub recv_window: u32,
    pub inflight: u32,
    pub send_queue_len: u32,
    pub recv_queue_len: u32,
    pub is_relayed: bool,
    pub fec_enabled: bool,
    pub encryption_enabled: bool,
    pub dns_disguise_enabled: bool,
    /// Remote peer address as string, e.g. "1.2.3.4:5678" or "[::1]:5678"
    pub remote_addr: String,
    /// Local UDP port used for this connection
    pub local_port: u16,
}
