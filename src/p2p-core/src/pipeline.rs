use std::sync::Arc;

use parking_lot::Mutex;

use crate::crypto::CryptoLayer;
use crate::dns_disguise::DnsDisguise;
use crate::fec::{FecDecoder, FecEncoder};
use crate::stats::ConnectionStats;

/// Packet processing pipeline that chains:
///   Send path: App Data → [FEC Encode] → [Encrypt] → [DNS Disguise] → Wire
///   Recv path: Wire → [DNS Unwrap] → [Decrypt] → [FEC Decode] → App Data
///
/// Each layer can be independently enabled/disabled at runtime.
pub struct PacketPipeline {
    pub fec_encoder: Mutex<FecEncoder>,
    pub fec_decoder: Mutex<FecDecoder>,
    pub crypto: Mutex<CryptoLayer>,
    pub dns_disguise: Mutex<DnsDisguise>,
    pub stats: Arc<ConnectionStats>,
}

impl PacketPipeline {
    pub fn new(stats: Arc<ConnectionStats>) -> Self {
        Self {
            fec_encoder: Mutex::new(FecEncoder::new(8, 2)),
            fec_decoder: Mutex::new(FecDecoder::new(8, 2)),
            crypto: Mutex::new(CryptoLayer::new_disabled()),
            dns_disguise: Mutex::new(DnsDisguise::new()),
            stats,
        }
    }

    /// Process a packet through the send pipeline.
    /// Returns multiple packets (FEC may expand one packet into several).
    pub fn process_outgoing(&self, data: &[u8]) -> Vec<Vec<u8>> {
        let mut packets = Vec::new();

        // Step 1: FEC encode (may produce multiple packets)
        let fec_packets = {
            let mut fec = self.fec_encoder.lock();
            fec.encode(data)
        };

        for fec_pkt in fec_packets {
            // Step 2: Encrypt
            let encrypted = {
                let crypto = self.crypto.lock();
                match crypto.encrypt(&fec_pkt) {
                    Ok(enc) => enc,
                    Err(e) => {
                        // When encryption is enabled, never fall back to plaintext —
                        // that would allow an attacker to force plaintext transmission.
                        tracing::warn!("Encryption failed: {}, dropping packet", e);
                        continue;
                    }
                }
            };

            // Step 3: DNS disguise
            let final_pkt = {
                let disguise = self.dns_disguise.lock();
                disguise.wrap(&encrypted)
            };

            self.stats.record_packet_sent();
            self.stats.record_bytes_written(final_pkt.len() as u64);

            packets.push(final_pkt);
        }

        // Record original application bytes separately (once, not per FEC packet)
        self.stats.record_bytes_read(0); // bytes_written already tracked above as wire bytes

        // Record FEC parity packets
        if packets.len() > 1 {
            for _ in 1..packets.len() {
                self.stats.record_fec_sent();
            }
        }

        packets
    }

    /// Process a packet through the receive pipeline.
    /// Returns decoded application data packets (may be empty if FEC is still
    /// accumulating, or multiple if FEC recovered lost packets).
    pub fn process_incoming(&self, wire_data: &[u8]) -> Vec<Vec<u8>> {
        self.stats.record_packet_recv();

        // Step 1: DNS unwrap
        let unwrapped = {
            let disguise = self.dns_disguise.lock();
            if disguise.is_enabled() && !disguise.is_transition_mode() {
                match disguise.unwrap(wire_data) {
                    Some(data) => data,
                    None => {
                        // DNS disguise is enabled but unwrap failed — drop the packet
                        // instead of falling back to raw data (which would allow bypass).
                        tracing::trace!("DNS unwrap failed while disguise enabled, dropping packet");
                        return Vec::new();
                    }
                }
            } else {
                // DNS disguise disabled or in transition mode:
                // try unwrap first, fall back to raw if it fails.
                match disguise.unwrap(wire_data) {
                    Some(data) => data,
                    None => wire_data.to_vec(),
                }
            }
        };

        // Step 2: Decrypt
        let decrypted = {
            let crypto = self.crypto.lock();
            match crypto.decrypt(&unwrapped) {
                Ok(plain) => plain,
                Err(e) => {
                    // When encryption is enabled, crypto.decrypt() now rejects
                    // plaintext-flagged packets (CryptoError::PlaintextRejected)
                    // and returns errors for auth failures. Never fall back to raw.
                    if crypto.is_enabled() {
                        tracing::trace!("Decryption failed while encryption enabled: {}, dropping", e);
                        return Vec::new();
                    }
                    // Encryption disabled: fall back to raw for non-encrypted packets
                    tracing::trace!("Decryption failed (encryption disabled): {}, using raw", e);
                    unwrapped
                }
            }
        };

        // Step 3: FEC decode
        let app_packets: Vec<Vec<u8>> = {
            let mut fec = self.fec_decoder.lock();
            fec.decode(&decrypted)
        };

        for pkt in &app_packets {
            self.stats.record_bytes_read(pkt.len() as u64);
        }

        app_packets
    }

    /// Flush FEC encoder (send any remaining parity packets).
    pub fn flush_fec(&self) -> Vec<Vec<u8>> {
        let fec_packets = {
            let mut fec = self.fec_encoder.lock();
            fec.flush()
        };

        let mut output = Vec::new();
        for fec_pkt in fec_packets {
            let encrypted = {
                let crypto = self.crypto.lock();
                match crypto.encrypt(&fec_pkt) {
                    Ok(enc) => enc,
                    Err(e) => {
                        tracing::warn!("Encryption failed during FEC flush: {}, dropping", e);
                        continue;
                    }
                }
            };
            let final_pkt = {
                let disguise = self.dns_disguise.lock();
                disguise.wrap(&encrypted)
            };
            self.stats.record_fec_sent();
            output.push(final_pkt);
        }
        output
    }

    // --- Runtime configuration ---

    pub fn enable_fec(&self, enabled: bool) {
        {
            let mut enc = self.fec_encoder.lock();
            enc.set_enabled(enabled);
        }
        {
            let mut dec = self.fec_decoder.lock();
            dec.set_enabled(enabled);
        }
        self.stats.fec_enabled.store(enabled, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn adapt_fec(&self, loss_percent: f32) {
        let mut enc = self.fec_encoder.lock();
        enc.adapt_to_loss(loss_percent);
    }

    pub fn enable_encryption(&self, key: &[u8; 32]) {
        let mut crypto = self.crypto.lock();
        crypto.enable(key);
        self.stats.encryption_enabled.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn disable_encryption(&self) {
        let mut crypto = self.crypto.lock();
        crypto.disable();
        self.stats.encryption_enabled.store(false, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn enable_dns_disguise(&self, enabled: bool) {
        let mut disguise = self.dns_disguise.lock();
        disguise.set_enabled(enabled);
        self.stats.dns_disguise_enabled.store(enabled, std::sync::atomic::Ordering::Relaxed);
    }

    // --- Negotiation transition methods ---

    /// Load an encryption key without enabling encrypted sending.
    /// Used by the negotiation initiator to prepare for receiving encrypted Acks.
    pub fn load_encryption_key_for_transition(&self, key: &[u8; 32]) {
        let mut crypto = self.crypto.lock();
        crypto.load_key_for_transition(key);
    }

    /// Promote from transition-loaded key to fully enabled encryption.
    /// Called when the negotiation Ack is received.
    pub fn enable_encryption_from_transition(&self) {
        let mut crypto = self.crypto.lock();
        crypto.enable_from_transition();
        self.stats.encryption_enabled.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// Set crypto transition mode (accept both plaintext and encrypted).
    pub fn set_crypto_transition(&self, active: bool) {
        let mut crypto = self.crypto.lock();
        crypto.set_transition_mode(active);
    }

    /// Set DNS disguise transition mode (accept both raw and disguised).
    pub fn set_dns_transition(&self, active: bool) {
        let mut disguise = self.dns_disguise.lock();
        disguise.set_transition_mode(active);
    }
}
