use reed_solomon_erasure::galois_8::ReedSolomon;

/// FEC (Forward Error Correction) layer using Reed-Solomon erasure coding.
///
/// Operates on groups of packets. For every `data_shards` data packets,
/// generates `parity_shards` parity packets. If up to `parity_shards`
/// packets in a group are lost, all original data can be recovered.
///
/// Block size adapts automatically based on observed packet loss rate.
pub struct FecEncoder {
    data_shards: usize,
    parity_shards: usize,
    rs: ReedSolomon,
    /// Current group of data packets being accumulated
    group_buffer: Vec<Option<Vec<u8>>>,
    /// Sequence number for the current FEC group
    group_seq: u32,
    /// Maximum packet size in current group (for padding)
    max_pkt_size: usize,
    enabled: bool,
}

pub struct FecDecoder {
    data_shards: usize,
    parity_shards: usize,
    rs: ReedSolomon,
    /// Buffered groups awaiting reconstruction: group_seq -> shards
    groups: std::collections::HashMap<u32, FecGroup>,
    enabled: bool,
}

struct FecGroup {
    shards: Vec<Option<Vec<u8>>>,
    received_count: usize,
    shard_size: usize,
    /// Timestamp when this group was first created (for GC).
    created_at: std::time::Instant,
}

/// FEC header prepended to each packet (8 bytes).
/// ```text
/// [group_seq: u32][shard_index: u16][shard_size: u16]
/// ```
const FEC_HEADER_SIZE: usize = 8;

impl FecEncoder {
    pub fn new(data_shards: usize, parity_shards: usize) -> Self {
        let rs = ReedSolomon::new(data_shards, parity_shards)
            .expect("Invalid FEC parameters");
        Self {
            data_shards,
            parity_shards,
            rs,
            group_buffer: Vec::with_capacity(data_shards),
            group_seq: 0,
            max_pkt_size: 0,
            enabled: false,
        }
    }

    /// Adapt FEC parameters based on current loss rate.
    /// Higher loss -> more parity shards.
    pub fn adapt_to_loss(&mut self, loss_percent: f32) {
        let (new_data, new_parity) = if loss_percent < 1.0 {
            (10, 1) // Very low loss: 10:1
        } else if loss_percent < 5.0 {
            (8, 2) // Low loss: 8:2
        } else if loss_percent < 10.0 {
            (6, 3) // Medium loss: 6:3
        } else if loss_percent < 20.0 {
            (4, 4) // High loss: 4:4
        } else {
            (3, 5) // Very high loss: 3:5
        };

        if new_data != self.data_shards || new_parity != self.parity_shards {
            // Flush current group before changing parameters
            tracing::info!(
                "FEC adapting: {}:{} -> {}:{} (loss={:.1}%)",
                self.data_shards, self.parity_shards,
                new_data, new_parity, loss_percent
            );
            self.data_shards = new_data;
            self.parity_shards = new_parity;
            self.rs = ReedSolomon::new(new_data, new_parity)
                .expect("Invalid FEC parameters");
            self.group_buffer.clear();
            self.max_pkt_size = 0;
        }
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        if !enabled {
            self.group_buffer.clear();
            self.max_pkt_size = 0;
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Feed a data packet into the FEC encoder.
    /// Returns a list of packets to send (may include parity packets
    /// when a group is complete).
    ///
    /// Each shard's data includes a 2-byte length prefix (`original_len: u16`)
    /// so that FEC recovery can determine the original packet size after
    /// reconstructing from padded shards. This is critical because data shards
    /// in a group often have different sizes (e.g., last KCP packet is smaller).
    pub fn encode(&mut self, data: &[u8]) -> Vec<Vec<u8>> {
        if !self.enabled {
            // Pass through with a minimal header indicating no FEC
            let mut pkt = Vec::with_capacity(1 + data.len());
            pkt.push(0x00); // Flag: no FEC
            pkt.extend_from_slice(data);
            return vec![pkt];
        }

        let mut output = Vec::new();

        // Build length-prefixed shard data: [orig_len: u16][data]
        // This prefix survives RS encoding/reconstruction and allows
        // recovering the original packet size after FEC recovery.
        let prefixed_len = 2 + data.len();
        let mut prefixed = Vec::with_capacity(prefixed_len);
        prefixed.extend_from_slice(&(data.len() as u16).to_be_bytes());
        prefixed.extend_from_slice(data);

        // Track max shard size (including length prefix) for uniform RS encoding
        if prefixed_len > self.max_pkt_size {
            self.max_pkt_size = prefixed_len;
        }

        self.group_buffer.push(Some(prefixed.clone()));

        // Emit the data packet with FEC header
        // shard_size = length-prefixed payload size
        let shard_index = (self.group_buffer.len() - 1) as u16;
        let mut pkt = Vec::with_capacity(1 + FEC_HEADER_SIZE + prefixed_len);
        pkt.push(0x01); // Flag: FEC enabled
        pkt.extend_from_slice(&self.group_seq.to_be_bytes());
        pkt.extend_from_slice(&shard_index.to_be_bytes());
        pkt.extend_from_slice(&(prefixed_len as u16).to_be_bytes());
        pkt.extend_from_slice(&prefixed);
        output.push(pkt);

        // When group is full, generate parity shards
        if self.group_buffer.len() == self.data_shards {
            let parity_pkts = self.generate_parity();
            output.extend(parity_pkts);
            self.group_seq = self.group_seq.wrapping_add(1);
            self.group_buffer.clear();
            self.max_pkt_size = 0;
        }

        output
    }

    /// Flush any remaining partial group (send data without full parity).
    pub fn flush(&mut self) -> Vec<Vec<u8>> {
        if !self.enabled || self.group_buffer.is_empty() {
            return Vec::new();
        }
        // Generate parity for the partial group using current count as data_shards
        let parity_pkts = self.generate_parity();
        let output = parity_pkts;
        self.group_seq = self.group_seq.wrapping_add(1);
        self.group_buffer.clear();
        self.max_pkt_size = 0;
        output
    }

    fn generate_parity(&self) -> Vec<Vec<u8>> {
        let shard_size = self.max_pkt_size;
        if shard_size == 0 {
            return Vec::new();
        }

        let total = self.data_shards + self.parity_shards;
        let mut shards: Vec<Vec<u8>> = Vec::with_capacity(total);

        // Pad data shards to uniform size (data already includes 2-byte length prefix)
        for shard_opt in &self.group_buffer {
            let mut s = vec![0u8; shard_size];
            if let Some(data) = shard_opt {
                s[..data.len()].copy_from_slice(data);
            }
            shards.push(s);
        }
        // Fill missing data shards with zeros
        while shards.len() < self.data_shards {
            shards.push(vec![0u8; shard_size]);
        }
        // Add empty parity shards
        for _ in 0..self.parity_shards {
            shards.push(vec![0u8; shard_size]);
        }

        // Generate parity
        let mut shard_refs: Vec<&mut [u8]> = shards.iter_mut().map(|s| s.as_mut_slice()).collect();
        if self.rs.encode(&mut shard_refs).is_err() {
            tracing::warn!("FEC encode failed");
            return Vec::new();
        }

        // Return parity shard packets with headers
        let mut output = Vec::new();
        for i in 0..self.parity_shards {
            let shard_index = (self.data_shards + i) as u16;
            let mut pkt = Vec::with_capacity(1 + FEC_HEADER_SIZE + shard_size);
            pkt.push(0x01); // Flag: FEC enabled
            pkt.extend_from_slice(&self.group_seq.to_be_bytes());
            pkt.extend_from_slice(&shard_index.to_be_bytes());
            pkt.extend_from_slice(&(shard_size as u16).to_be_bytes());
            pkt.extend_from_slice(&shards[self.data_shards + i]);
            output.push(pkt);
        }
        output
    }
}

impl FecDecoder {
    pub fn new(data_shards: usize, parity_shards: usize) -> Self {
        let rs = ReedSolomon::new(data_shards, parity_shards)
            .expect("Invalid FEC parameters");
        Self {
            data_shards,
            parity_shards,
            rs,
            groups: std::collections::HashMap::new(),
            enabled: false,
        }
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        if !enabled {
            self.groups.clear();
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn update_params(&mut self, data_shards: usize, parity_shards: usize) {
        if data_shards != self.data_shards || parity_shards != self.parity_shards {
            self.data_shards = data_shards;
            self.parity_shards = parity_shards;
            self.rs = ReedSolomon::new(data_shards, parity_shards)
                .expect("Invalid FEC parameters");
        }
    }

    /// Decode an incoming FEC-wrapped packet.
    /// Returns recovered data packets (if any).
    ///
    /// Each shard's data starts with a 2-byte length prefix (`original_len: u16`)
    /// embedded by the encoder, so we can recover the exact original packet size
    /// even after RS reconstruction from zero-padded shards.
    pub fn decode(&mut self, packet: &[u8]) -> Vec<Vec<u8>> {
        if packet.is_empty() {
            return Vec::new();
        }

        let flag = packet[0];
        if flag == 0x00 {
            // No FEC, pass through
            return vec![packet[1..].to_vec()];
        }

        if !self.enabled {
            // FEC decoder disabled — extract data from individual data shards.
            // This handles the transition when the remote encoder is already
            // enabled but the local decoder hasn't received the negotiation
            // message yet. Shard data includes a 2-byte length prefix that
            // must be stripped via extract_original_data().
            if packet.len() < 1 + FEC_HEADER_SIZE {
                return Vec::new();
            }
            let shard_index = u16::from_be_bytes([packet[5], packet[6]]) as usize;
            let shard_data = &packet[1 + FEC_HEADER_SIZE..];
            // Only extract from data shards; parity shards are useless
            // without reconstruction.
            if shard_index < self.data_shards {
                if let Some(app_data) = extract_original_data(shard_data) {
                    return vec![app_data];
                }
            }
            return Vec::new();
        }

        if packet.len() < 1 + FEC_HEADER_SIZE {
            return Vec::new();
        }

        let group_seq = u32::from_be_bytes([packet[1], packet[2], packet[3], packet[4]]);
        let shard_index = u16::from_be_bytes([packet[5], packet[6]]) as usize;
        let shard_size = u16::from_be_bytes([packet[7], packet[8]]) as usize;
        let shard_data = &packet[1 + FEC_HEADER_SIZE..];

        let total_shards = self.data_shards + self.parity_shards;

        let group = self.groups.entry(group_seq).or_insert_with(|| FecGroup {
            shards: (0..total_shards).map(|_| None).collect(),
            received_count: 0,
            shard_size,
            created_at: std::time::Instant::now(),
        });

        // Update shard_size to the maximum across all received shards.
        // Parity shards always carry shard_size = max_pkt_size (the uniform RS
        // shard size), so this correctly converges to max_pkt_size once any
        // parity shard arrives. Data shards may have smaller shard_size since
        // their payloads vary (last KCP packet in a burst is often smaller).
        if shard_size > group.shard_size {
            group.shard_size = shard_size;
        }

        // Store the shard's raw data (without truncation).
        // Padding to uniform size happens at RS reconstruction time.
        if shard_index < total_shards && group.shards[shard_index].is_none() {
            group.shards[shard_index] = Some(shard_data.to_vec());
            group.received_count += 1;
        }

        let mut output = Vec::new();

        // If it's a data shard, output it directly (extract original data from length prefix)
        if shard_index < self.data_shards {
            if let Some(app_data) = extract_original_data(shard_data) {
                output.push(app_data);
            }
        }

        // If we have enough shards, try to recover any missing data shards
        if group.received_count >= self.data_shards {
            let missing_data: Vec<usize> = (0..self.data_shards)
                .filter(|&i| group.shards[i].is_none())
                .collect();

            if !missing_data.is_empty() && group.received_count >= self.data_shards {
                // Need to reconstruct — pad all shards to uniform size
                let sz = group.shard_size;
                let mut shards: Vec<Option<Vec<u8>>> = group
                    .shards
                    .iter()
                    .map(|s| s.as_ref().map(|d| {
                        let mut padded = vec![0u8; sz];
                        let copy_len = d.len().min(sz);
                        padded[..copy_len].copy_from_slice(&d[..copy_len]);
                        padded
                    }))
                    .collect();

                match self.rs.reconstruct(&mut shards) {
                    Ok(_) => {
                        for idx in missing_data {
                            if let Some(ref data) = shards[idx] {
                                // Extract original data using the embedded length prefix
                                if let Some(app_data) = extract_original_data(data) {
                                    output.push(app_data);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            "FEC reconstruct failed for group {}: {:?}",
                            group_seq, e
                        );
                    }
                }
            }

            // Clean up completed group
            self.groups.remove(&group_seq);
        }

        // Garbage collect old groups using timestamps instead of group_seq.
        // group_seq uses wrapping_add(1) so u32::min() would break after wrap.
        // Use time-based eviction: remove groups older than 2 seconds, and if
        // still too many, batch-delete the oldest until we're under 48 entries.
        if self.groups.len() > 64 {
            let now = std::time::Instant::now();
            let stale_threshold = std::time::Duration::from_secs(2);

            // First pass: remove groups older than threshold
            self.groups.retain(|_, g| now.duration_since(g.created_at) < stale_threshold);

            // Second pass: if still too many, remove oldest by timestamp
            while self.groups.len() > 48 {
                if let Some(oldest_key) = self.groups.iter()
                    .min_by_key(|(_, g)| g.created_at)
                    .map(|(k, _)| *k)
                {
                    self.groups.remove(&oldest_key);
                } else {
                    break;
                }
            }
        }

        output
    }
}

/// Extract the original application data from a length-prefixed shard.
///
/// Shard format: `[original_len: u16 BE][original_data...]`
/// Returns `None` if the shard is too short or the embedded length exceeds available data.
fn extract_original_data(shard_data: &[u8]) -> Option<Vec<u8>> {
    if shard_data.len() < 2 {
        return None;
    }
    let orig_len = u16::from_be_bytes([shard_data[0], shard_data[1]]) as usize;
    if shard_data.len() < 2 + orig_len {
        return None;
    }
    Some(shard_data[2..2 + orig_len].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fec_roundtrip_no_loss() {
        let mut encoder = FecEncoder::new(4, 2);
        encoder.set_enabled(true);
        let mut decoder = FecDecoder::new(4, 2);
        decoder.set_enabled(true);

        // Simulate 4 data packets of different sizes
        let data_packets = vec![
            vec![1u8; 1376],  // Full KCP MSS
            vec![2u8; 1376],
            vec![3u8; 1376],
            vec![4u8; 500],   // Smaller last packet
        ];

        let mut all_wire_packets = Vec::new();
        for data in &data_packets {
            let encoded = encoder.encode(data);
            all_wire_packets.extend(encoded);
        }

        // Should have 4 data + 2 parity = 6 packets
        assert_eq!(all_wire_packets.len(), 6);

        // Decode all packets (no loss)
        let mut recovered = Vec::new();
        for wire_pkt in &all_wire_packets {
            let decoded = decoder.decode(wire_pkt);
            recovered.extend(decoded);
        }

        // Should recover exactly 4 data packets
        assert_eq!(recovered.len(), 4);
        assert_eq!(recovered[0], data_packets[0]);
        assert_eq!(recovered[1], data_packets[1]);
        assert_eq!(recovered[2], data_packets[2]);
        assert_eq!(recovered[3], data_packets[3]);
    }

    #[test]
    fn test_fec_roundtrip_with_loss() {
        let mut encoder = FecEncoder::new(4, 2);
        encoder.set_enabled(true);
        let mut decoder = FecDecoder::new(4, 2);
        decoder.set_enabled(true);

        // Data packets with different sizes (the key scenario)
        let data_packets = vec![
            vec![1u8; 1376],
            vec![2u8; 1376],
            vec![3u8; 1376],
            vec![4u8; 500],   // Smaller last packet
        ];

        let mut all_wire_packets = Vec::new();
        for data in &data_packets {
            let encoded = encoder.encode(data);
            all_wire_packets.extend(encoded);
        }

        // Simulate loss: drop data shard 0 (index 0) — the 1376-byte one
        // Keep: shard 1, 2, 3, parity 0, parity 1
        let mut recovered = Vec::new();
        for (i, wire_pkt) in all_wire_packets.iter().enumerate() {
            if i == 0 { continue; } // Drop shard 0
            let decoded = decoder.decode(wire_pkt);
            recovered.extend(decoded);
        }

        // Should recover 4 packets: shards 1,2,3 directly + shard 0 via reconstruction
        assert_eq!(recovered.len(), 4);

        // Direct outputs: shards 1, 2, 3
        assert_eq!(recovered[0], data_packets[1]);
        assert_eq!(recovered[1], data_packets[2]);
        assert_eq!(recovered[2], data_packets[3]);

        // Reconstructed shard 0 (the 1376-byte one!)
        assert_eq!(recovered[3].len(), 1376);
        assert_eq!(recovered[3], data_packets[0]);
    }

    #[test]
    fn test_fec_roundtrip_loss_small_shard() {
        let mut encoder = FecEncoder::new(4, 2);
        encoder.set_enabled(true);
        let mut decoder = FecDecoder::new(4, 2);
        decoder.set_enabled(true);

        let data_packets = vec![
            vec![1u8; 1376],
            vec![2u8; 1376],
            vec![3u8; 1376],
            vec![4u8; 500],
        ];

        let mut all_wire_packets = Vec::new();
        for data in &data_packets {
            let encoded = encoder.encode(data);
            all_wire_packets.extend(encoded);
        }

        // Drop the small shard (index 3, 500 bytes)
        let mut recovered = Vec::new();
        for (i, wire_pkt) in all_wire_packets.iter().enumerate() {
            if i == 3 { continue; } // Drop shard 3
            let decoded = decoder.decode(wire_pkt);
            recovered.extend(decoded);
        }

        assert_eq!(recovered.len(), 4);
        assert_eq!(recovered[0], data_packets[0]);
        assert_eq!(recovered[1], data_packets[1]);
        assert_eq!(recovered[2], data_packets[2]);
        // Reconstructed small shard
        assert_eq!(recovered[3].len(), 500);
        assert_eq!(recovered[3], data_packets[3]);
    }

    #[test]
    fn test_fec_no_fec_passthrough() {
        let mut encoder = FecEncoder::new(4, 2);
        // FEC disabled
        let mut decoder = FecDecoder::new(4, 2);

        let data = vec![42u8; 100];
        let encoded = encoder.encode(&data);
        assert_eq!(encoded.len(), 1);

        let decoded = decoder.decode(&encoded[0]);
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0], data);
    }
}
