use rand::RngCore;

/// DNS protocol disguise layer.
///
/// Wraps data packets to look like DNS query/response traffic.
/// This helps bypass firewalls and DPI (Deep Packet Inspection)
/// that block non-standard UDP traffic.
///
/// The disguise wraps data as:
/// - Outgoing: DNS query (type TXT) to a fake domain
/// - Incoming: DNS response with TXT record containing the real data
///
/// DNS packet format (simplified):
/// ```text
/// [Transaction ID: 2 bytes]
/// [Flags: 2 bytes]
/// [Questions: 2 bytes]
/// [Answer RRs: 2 bytes]
/// [Authority RRs: 2 bytes]
/// [Additional RRs: 2 bytes]
/// [Query/Answer data...]
/// ```
pub struct DnsDisguise {
    enabled: bool,
    /// Transition mode: temporarily accept both disguised and raw packets.
    /// Used during DNS disguise negotiation to avoid packet loss while peers
    /// switch formats.
    transition_mode: bool,
}

const DNS_HEADER_SIZE: usize = 12;
// Minimal DNS query name + type + class overhead
const DNS_QUERY_OVERHEAD: usize = 20;

// Flag byte prepended to indicate whether disguise is active
const DISGUISE_FLAG_OFF: u8 = 0x00;
const DISGUISE_FLAG_DNS: u8 = 0x01;

impl DnsDisguise {
    pub fn new() -> Self {
        Self {
            enabled: false,
            transition_mode: false,
        }
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        if !enabled {
            self.transition_mode = false;
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Enable/disable transition mode.
    ///
    /// In transition mode, `unwrap()` accepts both DNS-disguised and raw
    /// packets regardless of the `enabled` flag. This provides a short window
    /// during negotiation where in-flight packets of either format are handled.
    pub fn set_transition_mode(&mut self, active: bool) {
        self.transition_mode = active;
    }

    pub fn is_transition_mode(&self) -> bool {
        self.transition_mode
    }

    /// Wrap data to look like a DNS query packet.
    pub fn wrap(&self, data: &[u8]) -> Vec<u8> {
        if !self.enabled {
            let mut out = Vec::with_capacity(1 + data.len());
            out.push(DISGUISE_FLAG_OFF);
            out.extend_from_slice(data);
            return out;
        }

        let mut pkt = Vec::with_capacity(1 + DNS_HEADER_SIZE + DNS_QUERY_OVERHEAD + data.len());
        pkt.push(DISGUISE_FLAG_DNS);

        // Transaction ID (random)
        let mut txn_id = [0u8; 2];
        rand::thread_rng().fill_bytes(&mut txn_id);
        pkt.extend_from_slice(&txn_id);

        // Flags: Standard query (0x0100) or Response (0x8180)
        // We use query format for outgoing
        pkt.extend_from_slice(&[0x01, 0x00]);

        // Questions: 1, Answers: 0, Authority: 0, Additional: 0
        pkt.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
        pkt.extend_from_slice(&[0x00, 0x00]); // ANCOUNT
        pkt.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
        pkt.extend_from_slice(&[0x00, 0x00]); // ARCOUNT

        // Query Name: encode data length as part of the "domain name"
        // Format: [len_high][len_low][label_len]"d"[data...][0x00]
        // We embed the data as a DNS name label sequence
        let data_len = data.len() as u16;
        // First label: 2 bytes for data length
        pkt.push(2); // label length
        pkt.extend_from_slice(&data_len.to_be_bytes());

        // Subsequent labels: pack data in chunks of 63 bytes (DNS label max)
        let mut offset = 0;
        while offset < data.len() {
            let chunk_len = (data.len() - offset).min(63);
            pkt.push(chunk_len as u8);
            pkt.extend_from_slice(&data[offset..offset + chunk_len]);
            offset += chunk_len;
        }
        // Null terminator for domain name
        pkt.push(0x00);

        // Query Type: TXT (0x0010)
        pkt.extend_from_slice(&[0x00, 0x10]);
        // Query Class: IN (0x0001)
        pkt.extend_from_slice(&[0x00, 0x01]);

        pkt
    }

    /// Unwrap a DNS-disguised packet to extract the original data.
    pub fn unwrap(&self, packet: &[u8]) -> Option<Vec<u8>> {
        if packet.is_empty() {
            return None;
        }

        let flag = packet[0];

        if flag == DISGUISE_FLAG_OFF {
            return Some(packet[1..].to_vec());
        }

        if flag != DISGUISE_FLAG_DNS {
            return None;
        }

        // Skip the flag byte + DNS header (12 bytes)
        if packet.len() < 1 + DNS_HEADER_SIZE + 3 {
            return None;
        }

        let dns_data = &packet[1 + DNS_HEADER_SIZE..];

        // Read the first label (2 bytes containing data length)
        if dns_data.len() < 3 || dns_data[0] != 2 {
            return None;
        }
        let data_len = u16::from_be_bytes([dns_data[1], dns_data[2]]) as usize;

        // Read subsequent labels to reconstruct data
        let mut result = Vec::with_capacity(data_len);
        let mut offset = 3; // skip first label

        while offset < dns_data.len() {
            let label_len = dns_data[offset] as usize;
            if label_len == 0 {
                break; // null terminator
            }
            offset += 1;
            if offset + label_len > dns_data.len() {
                break;
            }
            result.extend_from_slice(&dns_data[offset..offset + label_len]);
            offset += label_len;
        }

        result.truncate(data_len);
        Some(result)
    }

    /// Get the overhead in bytes added by DNS disguise per packet.
    pub fn overhead(&self, data_len: usize) -> usize {
        if !self.enabled {
            return 1; // flag byte only
        }
        // flag + DNS header + first label (3) + data labels overhead + null + type + class
        let label_count = (data_len + 62) / 63; // number of labels needed
        1 + DNS_HEADER_SIZE + 3 + label_count + 1 + 4
    }
}

impl Default for DnsDisguise {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_disabled() {
        let disguise = DnsDisguise::new();
        let data = b"hello world";
        let wrapped = disguise.wrap(data);
        let unwrapped = disguise.unwrap(&wrapped).unwrap();
        assert_eq!(&unwrapped, data);
    }

    #[test]
    fn test_roundtrip_enabled() {
        let mut disguise = DnsDisguise::new();
        disguise.set_enabled(true);
        let data = b"hello world, this is a test of DNS disguise";
        let wrapped = disguise.wrap(data);
        let unwrapped = disguise.unwrap(&wrapped).unwrap();
        assert_eq!(&unwrapped, &data[..]);
    }

    #[test]
    fn test_roundtrip_large_data() {
        let mut disguise = DnsDisguise::new();
        disguise.set_enabled(true);
        let data: Vec<u8> = (0..500).map(|i| (i % 256) as u8).collect();
        let wrapped = disguise.wrap(&data);
        let unwrapped = disguise.unwrap(&wrapped).unwrap();
        assert_eq!(unwrapped, data);
    }
}
