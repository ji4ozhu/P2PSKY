use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit},
};
use rand::{RngCore, rngs::OsRng};

/// Encryption layer using ChaCha20-Poly1305 AEAD.
///
/// Provides optional packet-level encryption with authenticated encryption.
/// Each packet gets a unique nonce (random 12 bytes prepended to ciphertext).
///
/// Overhead: 12 bytes nonce + 16 bytes auth tag = 28 bytes per packet.
pub struct CryptoLayer {
    cipher: Option<ChaCha20Poly1305>,
    enabled: bool,
    /// Transition mode: temporarily accept both plaintext and encrypted packets.
    /// Used during encryption negotiation to avoid packet loss while peers
    /// switch from plaintext to encrypted mode (or vice versa).
    transition_mode: bool,
}

/// Encrypted packet format:
/// ```text
/// [flag: u8][nonce: 12 bytes][ciphertext + tag: N + 16 bytes]
/// ```
/// Unencrypted format:
/// ```text
/// [flag: u8][plaintext: N bytes]
/// ```
const CRYPTO_FLAG_PLAIN: u8 = 0x00;
const CRYPTO_FLAG_ENCRYPTED: u8 = 0x01;
const NONCE_SIZE: usize = 12;
const TAG_SIZE: usize = 16;

impl CryptoLayer {
    /// Create a new crypto layer in disabled state (plaintext pass-through).
    pub fn new_disabled() -> Self {
        Self {
            cipher: None,
            enabled: false,
            transition_mode: false,
        }
    }

    /// Create a new crypto layer with the given 32-byte key.
    pub fn new_with_key(key: &[u8; 32]) -> Self {
        let key = Key::from_slice(key);
        let cipher = ChaCha20Poly1305::new(key);
        Self {
            cipher: Some(cipher),
            enabled: true,
            transition_mode: false,
        }
    }

    /// Enable encryption with the given key.
    pub fn enable(&mut self, key: &[u8; 32]) {
        let k = Key::from_slice(key);
        self.cipher = Some(ChaCha20Poly1305::new(k));
        self.enabled = true;
    }

    /// Disable encryption (plaintext pass-through).
    /// L1: Clears the cipher to prevent key material from lingering in memory.
    pub fn disable(&mut self) {
        self.enabled = false;
        self.transition_mode = false;
        self.cipher = None;
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Load a key without enabling encrypted sending.
    ///
    /// Used by the negotiation initiator: the cipher is loaded so incoming
    /// encrypted packets (e.g., the ConfigAck) can be decrypted, but outgoing
    /// packets are still sent as plaintext until the Ack is received.
    pub fn load_key_for_transition(&mut self, key: &[u8; 32]) {
        let k = Key::from_slice(key);
        self.cipher = Some(ChaCha20Poly1305::new(k));
        // enabled stays false — encrypt() still produces plaintext
    }

    /// Promote from transition-loaded key to fully enabled.
    ///
    /// Called after the negotiation Ack is received. The cipher was already
    /// loaded by `load_key_for_transition()`, so we just flip `enabled`.
    pub fn enable_from_transition(&mut self) {
        if self.cipher.is_some() {
            self.enabled = true;
        }
    }

    /// Enable/disable transition mode.
    ///
    /// In transition mode, `decrypt()` accepts both plaintext and encrypted
    /// packets regardless of the `enabled` flag. This provides a short window
    /// during negotiation where in-flight packets of either format are handled.
    pub fn set_transition_mode(&mut self, active: bool) {
        self.transition_mode = active;
    }

    /// Encrypt a packet. Returns the encrypted packet with nonce prepended.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if !self.enabled {
            let mut out = Vec::with_capacity(1 + plaintext.len());
            out.push(CRYPTO_FLAG_PLAIN);
            out.extend_from_slice(plaintext);
            return Ok(out);
        }

        let cipher = self.cipher.as_ref().ok_or(CryptoError::NotInitialized)?;

        // M14: Use OsRng for cryptographic nonce generation.
        // thread_rng() may use a userspace CSPRNG seeded from the OS,
        // but OsRng goes directly to the OS entropy source, which is
        // the correct choice for AEAD nonces.
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| CryptoError::EncryptionFailed)?;

        let mut out = Vec::with_capacity(1 + NONCE_SIZE + ciphertext.len());
        out.push(CRYPTO_FLAG_ENCRYPTED);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Decrypt a packet. Handles both encrypted and plaintext packets.
    pub fn decrypt(&self, packet: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if packet.is_empty() {
            return Err(CryptoError::PacketTooShort);
        }

        let flag = packet[0];

        if flag == CRYPTO_FLAG_PLAIN {
            if self.enabled && !self.transition_mode {
                // Reject plaintext packets when encryption is enabled —
                // accepting them would let an attacker bypass encryption entirely.
                return Err(CryptoError::PlaintextRejected);
            }
            // Plaintext pass-through:
            // - encryption disabled, OR
            // - transition mode (temporarily accepting both formats)
            return Ok(packet[1..].to_vec());
        }

        if flag != CRYPTO_FLAG_ENCRYPTED {
            return Err(CryptoError::InvalidFlag);
        }

        if packet.len() < 1 + NONCE_SIZE + TAG_SIZE {
            return Err(CryptoError::PacketTooShort);
        }

        let cipher = self.cipher.as_ref().ok_or(CryptoError::NotInitialized)?;

        let nonce = Nonce::from_slice(&packet[1..1 + NONCE_SIZE]);
        let ciphertext = &packet[1 + NONCE_SIZE..];

        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| CryptoError::DecryptionFailed)
    }

    /// Get the overhead in bytes added by encryption per packet.
    pub fn overhead(&self) -> usize {
        if self.enabled {
            1 + NONCE_SIZE + TAG_SIZE // flag + nonce + auth tag
        } else {
            1 // flag byte only
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Crypto not initialized (no key set)")]
    NotInitialized,
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed (authentication error)")]
    DecryptionFailed,
    #[error("Packet too short")]
    PacketTooShort,
    #[error("Invalid packet flag")]
    InvalidFlag,
    #[error("Plaintext packet rejected (encryption is enabled)")]
    PlaintextRejected,
}
