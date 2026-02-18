/// Pipeline configuration negotiation protocol.
///
/// Enables automatic synchronization of FEC / Encryption / DNS Disguise
/// settings between peers through in-band KCP control messages.
///
/// ## Framing
///
/// All KCP application-layer messages carry a 1-byte type prefix:
/// - `0x00` — application data (forwarded to `receive_cb`)
/// - `0x01` — control message (handled internally)
///
/// ## Control Message Format
///
/// ```text
/// [msg_type:u8][seq:u8][feature:u8][action:u8][payload...]
/// ```
///
/// - `msg_type`: `0x01` = ConfigRequest, `0x02` = ConfigAck
/// - `seq`: sequence number for request/ack correlation
/// - `feature`: which pipeline layer
/// - `action`: enable or disable
/// - `payload`: feature-specific data (e.g., 32-byte key for encryption)

use std::sync::atomic::{AtomicU8, Ordering};

// --- Frame type prefixes (prepended to KCP application data) ---

/// Application data frame prefix.
pub const FRAME_APP_DATA: u8 = 0x00;
/// Control message frame prefix.
pub const FRAME_CONTROL: u8 = 0x01;

// --- Control message types ---

pub const MSG_CONFIG_REQUEST: u8 = 0x01;
pub const MSG_CONFIG_ACK: u8 = 0x02;

// --- Feature identifiers ---

pub const FEATURE_FEC: u8 = 0x01;
pub const FEATURE_ENCRYPTION: u8 = 0x02;
pub const FEATURE_DNS_DISGUISE: u8 = 0x03;

// --- Action identifiers ---

pub const ACTION_ENABLE: u8 = 0x01;
pub const ACTION_DISABLE: u8 = 0x02;

// --- Ack status codes ---

pub const STATUS_OK: u8 = 0x01;
pub const STATUS_REJECTED: u8 = 0x02;

// --- Minimum message sizes ---

/// Minimum ConfigRequest size: msg_type(1) + seq(1) + feature(1) + action(1) = 4
const MIN_REQUEST_SIZE: usize = 4;
/// Minimum ConfigAck size: msg_type(1) + seq(1) + feature(1) + action(1) + status(1) = 5
const MIN_ACK_SIZE: usize = 5;

/// Global sequence counter for outgoing requests.
static SEQ_COUNTER: AtomicU8 = AtomicU8::new(0);

fn next_seq() -> u8 {
    SEQ_COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// Parsed control message.
#[derive(Debug, Clone, PartialEq)]
pub enum ControlMessage {
    ConfigRequest(ConfigRequest),
    ConfigAck(ConfigAck),
}

#[derive(Debug, Clone, PartialEq)]
pub struct ConfigRequest {
    pub seq: u8,
    pub feature: u8,
    pub action: u8,
    /// 32-byte encryption key (only present for Encryption Enable requests).
    pub key: Option<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ConfigAck {
    pub seq: u8,
    pub feature: u8,
    pub action: u8,
    pub status: u8,
}

/// Build a ConfigRequest control message (without the FRAME_CONTROL prefix).
///
/// The caller must prepend `FRAME_CONTROL` before sending through KCP.
pub fn build_config_request(feature: u8, action: u8, key: Option<&[u8; 32]>) -> Vec<u8> {
    let seq = next_seq();
    let key_len = if key.is_some() { 32 } else { 0 };
    let mut msg = Vec::with_capacity(MIN_REQUEST_SIZE + key_len);
    msg.push(MSG_CONFIG_REQUEST);
    msg.push(seq);
    msg.push(feature);
    msg.push(action);
    if let Some(k) = key {
        msg.extend_from_slice(k);
    }
    msg
}

/// Build a ConfigAck control message (without the FRAME_CONTROL prefix).
pub fn build_config_ack(seq: u8, feature: u8, action: u8, status: u8) -> Vec<u8> {
    vec![MSG_CONFIG_ACK, seq, feature, action, status]
}

/// Parse a control message from raw bytes (after stripping the FRAME_CONTROL prefix).
pub fn parse_control_message(data: &[u8]) -> Result<ControlMessage, &'static str> {
    if data.is_empty() {
        return Err("empty control message");
    }

    let msg_type = data[0];

    match msg_type {
        MSG_CONFIG_REQUEST => {
            if data.len() < MIN_REQUEST_SIZE {
                return Err("ConfigRequest too short");
            }
            let seq = data[1];
            let feature = data[2];
            let action = data[3];

            let key = if feature == FEATURE_ENCRYPTION && action == ACTION_ENABLE {
                if data.len() < MIN_REQUEST_SIZE + 32 {
                    return Err("ConfigRequest missing encryption key");
                }
                let mut k = [0u8; 32];
                k.copy_from_slice(&data[MIN_REQUEST_SIZE..MIN_REQUEST_SIZE + 32]);
                Some(k)
            } else {
                None
            };

            Ok(ControlMessage::ConfigRequest(ConfigRequest {
                seq,
                feature,
                action,
                key,
            }))
        }
        MSG_CONFIG_ACK => {
            if data.len() < MIN_ACK_SIZE {
                return Err("ConfigAck too short");
            }
            Ok(ControlMessage::ConfigAck(ConfigAck {
                seq: data[1],
                feature: data[2],
                action: data[3],
                status: data[4],
            }))
        }
        _ => Err("unknown control message type"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_request_fec_enable() {
        let msg = build_config_request(FEATURE_FEC, ACTION_ENABLE, None);
        assert_eq!(msg[0], MSG_CONFIG_REQUEST);
        assert_eq!(msg[2], FEATURE_FEC);
        assert_eq!(msg[3], ACTION_ENABLE);
        assert_eq!(msg.len(), 4);

        let parsed = parse_control_message(&msg).unwrap();
        if let ControlMessage::ConfigRequest(req) = parsed {
            assert_eq!(req.feature, FEATURE_FEC);
            assert_eq!(req.action, ACTION_ENABLE);
            assert!(req.key.is_none());
        } else {
            panic!("expected ConfigRequest");
        }
    }

    #[test]
    fn test_config_request_encryption_enable_with_key() {
        let key = [0xABu8; 32];
        let msg = build_config_request(FEATURE_ENCRYPTION, ACTION_ENABLE, Some(&key));
        assert_eq!(msg.len(), 4 + 32);
        assert_eq!(msg[0], MSG_CONFIG_REQUEST);
        assert_eq!(msg[2], FEATURE_ENCRYPTION);
        assert_eq!(msg[3], ACTION_ENABLE);

        let parsed = parse_control_message(&msg).unwrap();
        if let ControlMessage::ConfigRequest(req) = parsed {
            assert_eq!(req.feature, FEATURE_ENCRYPTION);
            assert_eq!(req.action, ACTION_ENABLE);
            assert_eq!(req.key, Some(key));
        } else {
            panic!("expected ConfigRequest");
        }
    }

    #[test]
    fn test_config_request_dns_disable() {
        let msg = build_config_request(FEATURE_DNS_DISGUISE, ACTION_DISABLE, None);
        let parsed = parse_control_message(&msg).unwrap();
        if let ControlMessage::ConfigRequest(req) = parsed {
            assert_eq!(req.feature, FEATURE_DNS_DISGUISE);
            assert_eq!(req.action, ACTION_DISABLE);
            assert!(req.key.is_none());
        } else {
            panic!("expected ConfigRequest");
        }
    }

    #[test]
    fn test_config_ack_roundtrip() {
        let ack = build_config_ack(42, FEATURE_FEC, ACTION_ENABLE, STATUS_OK);
        assert_eq!(ack.len(), 5);

        let parsed = parse_control_message(&ack).unwrap();
        if let ControlMessage::ConfigAck(a) = parsed {
            assert_eq!(a.seq, 42);
            assert_eq!(a.feature, FEATURE_FEC);
            assert_eq!(a.action, ACTION_ENABLE);
            assert_eq!(a.status, STATUS_OK);
        } else {
            panic!("expected ConfigAck");
        }
    }

    #[test]
    fn test_parse_errors() {
        assert!(parse_control_message(&[]).is_err());
        assert!(parse_control_message(&[MSG_CONFIG_REQUEST]).is_err()); // too short
        assert!(parse_control_message(&[MSG_CONFIG_ACK, 0, 0, 0]).is_err()); // too short
        assert!(parse_control_message(&[0xFF, 0, 0, 0]).is_err()); // unknown type

        // Encryption request without key
        let bad = vec![MSG_CONFIG_REQUEST, 0, FEATURE_ENCRYPTION, ACTION_ENABLE];
        assert!(parse_control_message(&bad).is_err());
    }

    #[test]
    fn test_seq_counter_increments() {
        let msg1 = build_config_request(FEATURE_FEC, ACTION_ENABLE, None);
        let msg2 = build_config_request(FEATURE_FEC, ACTION_ENABLE, None);
        // seq should differ (wrapping is fine)
        assert_ne!(msg1[1], msg2[1]);
    }
}
