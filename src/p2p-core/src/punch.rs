use std::collections::HashSet;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

use crate::candidate::Candidate;
use crate::dual_stack::DualStackSocket;

/// M6: Global counter for birthday sockets across all connections.
/// Prevents resource exhaustion when many connections start simultaneously.
static GLOBAL_BIRTHDAY_SOCKETS: AtomicUsize = AtomicUsize::new(0);
const MAX_GLOBAL_BIRTHDAY_SOCKETS: usize = 256;

/// Magic bytes for punch probe packets: "P2P1" (0x50 0x32 0x50 0x31)
pub const PROBE_MAGIC: [u8; 4] = [0x50, 0x32, 0x50, 0x31];
const PROBE_REQUEST: u8 = 0x01;
const PROBE_RESPONSE: u8 = 0x02;
const PROBE_SIZE: usize = 17; // 4 magic + 1 type + 8 nonce + 4 session_hash

/// Check if a UDP packet is a punch probe by inspecting magic bytes.
pub fn is_punch_probe(data: &[u8]) -> bool {
    data.len() >= PROBE_SIZE && data[0..4] == PROBE_MAGIC
}

/// Parsed punch probe content.
pub struct ProbeInfo {
    pub probe_type: u8,
    pub nonce: [u8; 8],
    pub session_hash: [u8; 4],
}

/// Parse a punch probe packet.
pub fn parse_probe(data: &[u8]) -> Option<ProbeInfo> {
    if !is_punch_probe(data) {
        return None;
    }
    let probe_type = data[4];
    let mut nonce = [0u8; 8];
    nonce.copy_from_slice(&data[5..13]);
    let mut session_hash = [0u8; 4];
    session_hash.copy_from_slice(&data[13..17]);
    Some(ProbeInfo {
        probe_type,
        nonce,
        session_hash,
    })
}

/// Compute a 4-byte hash from the session_id for probe validation.
pub fn compute_session_hash(session_id: &str) -> [u8; 4] {
    let mut hash: u32 = 0x811c9dc5; // FNV-1a offset basis
    for b in session_id.bytes() {
        hash ^= b as u32;
        hash = hash.wrapping_mul(0x01000193); // FNV-1a prime
    }
    hash.to_le_bytes()
}

/// Derive a KCP conversation ID from the session_id.
/// Both peers compute the same conv_id independently.
///
/// The low byte of the conv_id (wire byte 0) is forced to have its high bit
/// set (>= 0x80). This prevents the UDP demultiplexer from misclassifying
/// KCP packets as TURN ChannelData (0x4000-0x7FFF), STUN (0x00-0x01), or
/// punch probes (0x50 = 'P').
pub fn derive_conv_id(session_id: &str) -> u32 {
    let hash = compute_session_hash(session_id);
    let mut conv = u32::from_le_bytes(hash);
    // Ensure non-zero (KCP requires conv_id > 0)
    if conv == 0 { conv = 1; }
    // Force low byte high bit → wire byte[0] >= 0x80, never confused with
    // TURN (0x40-0x7F), STUN (0x00-0x01), or punch probe (0x50 'P').
    conv |= 0x80;
    conv
}

/// Build a probe packet.
fn build_probe(probe_type: u8, nonce: &[u8; 8], session_hash: &[u8; 4]) -> [u8; PROBE_SIZE] {
    let mut pkt = [0u8; PROBE_SIZE];
    pkt[0..4].copy_from_slice(&PROBE_MAGIC);
    pkt[4] = probe_type;
    pkt[5..13].copy_from_slice(nonce);
    pkt[13..17].copy_from_slice(session_hash);
    pkt
}

/// Result of a successful hole punch.
#[derive(Debug, Clone)]
pub struct PunchResult {
    pub remote_addr: SocketAddr,
}

/// Detect symmetric NAT from multiple srflx candidates sharing the same IP
/// but having different ports, then predict additional target ports using the
/// observed allocation delta.
///
/// Returns new predicted `SocketAddr` targets. `analyzed_ips` tracks which IPs
/// have already been analyzed to avoid duplicating work when new candidates arrive.
fn generate_port_predictions(
    candidates: &[Candidate],
    analyzed_ips: &mut HashSet<IpAddr>,
) -> Vec<SocketAddr> {
    use p2p_signaling_proto::CandidateType;

    // Group srflx candidates by IP
    let mut ip_ports: HashMap<IpAddr, Vec<u16>> = HashMap::new();
    for c in candidates {
        if c.candidate_type == CandidateType::ServerReflexive {
            ip_ports.entry(c.address.ip()).or_default().push(c.address.port());
        }
    }

    let mut predictions = Vec::new();

    for (ip, mut ports) in ip_ports {
        // Skip IPs we've already analyzed
        if analyzed_ips.contains(&ip) {
            continue;
        }

        ports.sort();
        ports.dedup();

        if ports.len() < 2 {
            continue; // Cone NAT or only 1 result — no prediction possible
        }

        // Symmetric NAT detected!
        analyzed_ips.insert(ip);

        // Calculate deltas between consecutive observed ports
        let deltas: Vec<i32> = ports.windows(2)
            .map(|w| w[1] as i32 - w[0] as i32)
            .collect();

        // Use median delta (robust against outliers from interleaved allocations)
        let mut sorted_deltas = deltas.clone();
        sorted_deltas.sort();
        let median_delta = sorted_deltas[sorted_deltas.len() / 2];

        if median_delta <= 0 || median_delta > 200 {
            continue; // Unreasonable delta
        }

        let max_port = *ports.last().unwrap();
        let min_port = ports[0];

        // Predict forward from the highest observed port
        let forward_count = (30i32).min(500 / median_delta); // Cap total range at ~500 ports
        for i in 1..=forward_count {
            let predicted = max_port as i32 + i * median_delta;
            if predicted > 0 && predicted <= 65535 {
                predictions.push(SocketAddr::new(ip, predicted as u16));
            }
        }

        // Predict backward from the lowest observed port (fewer, in case of timing jitter)
        for i in 1..=5i32 {
            let predicted = min_port as i32 - i * median_delta;
            if predicted > 1024 && predicted <= 65535 {
                predictions.push(SocketAddr::new(ip, predicted as u16));
            }
        }

        tracing::info!(
            "Symmetric NAT detected for {}: observed ports {:?}, delta={}, predicted {} extra targets",
            ip,
            ports,
            median_delta,
            predictions.len(),
        );
    }

    predictions
}

// ---------------------------------------------------------------------------
// Birthday Attack: multi-socket parallel probing for symmetric NAT traversal
// ---------------------------------------------------------------------------

/// Number of birthday sockets to open per address family.
const BIRTHDAY_SOCKET_COUNT: usize = 64;

/// Probe interval for each birthday socket (slower than main 25ms to limit bandwidth).
const BIRTHDAY_PROBE_INTERVAL: Duration = Duration::from_millis(200);

/// RAII guard that aborts all birthday socket tasks on drop
/// and decrements the global socket counter.
struct BirthdayGuard {
    handles: Vec<tokio::task::JoinHandle<()>>,
    socket_count: usize,
}

impl Drop for BirthdayGuard {
    fn drop(&mut self) {
        for h in self.handles.drain(..) {
            h.abort();
        }
        GLOBAL_BIRTHDAY_SOCKETS.fetch_sub(self.socket_count, Ordering::Relaxed);
    }
}

/// Check if candidates show signs of symmetric NAT (multiple srflx from same IP
/// with different ports).
fn is_symmetric_nat(candidates: &[Candidate]) -> bool {
    use p2p_signaling_proto::CandidateType;
    let mut ip_ports: HashMap<IpAddr, HashSet<u16>> = HashMap::new();
    for c in candidates {
        if c.candidate_type == CandidateType::ServerReflexive {
            ip_ports.entry(c.address.ip()).or_default().insert(c.address.port());
        }
    }
    ip_ports.values().any(|ports| ports.len() >= 2)
}

/// Task for a single birthday socket: probe all targets, listen for responses.
async fn birthday_socket_task(
    index: usize,
    socket: Arc<tokio::net::UdpSocket>,
    targets: Vec<SocketAddr>,
    session_hash: [u8; 4],
    tx: mpsc::UnboundedSender<SocketAddr>,
) {
    let socket_is_v4 = socket.local_addr().map(|a| a.is_ipv4()).unwrap_or(true);
    let mut send_timer = tokio::time::interval(BIRTHDAY_PROBE_INTERVAL);
    let mut buf = [0u8; PROBE_SIZE + 64];

    loop {
        tokio::select! {
            _ = send_timer.tick() => {
                let mut nonce = [0u8; 8];
                use rand::RngCore;
                rand::thread_rng().fill_bytes(&mut nonce);
                let probe = build_probe(PROBE_REQUEST, &nonce, &session_hash);

                for &addr in &targets {
                    if addr.is_ipv4() == socket_is_v4 {
                        let _ = socket.send_to(&probe, addr).await;
                    }
                }
            }
            result = socket.recv_from(&mut buf) => {
                match result {
                    Ok((len, from_addr)) => {
                        if let Some(info) = parse_probe(&buf[..len]) {
                            if info.session_hash != session_hash {
                                continue;
                            }
                            match info.probe_type {
                                PROBE_REQUEST => {
                                    let response = build_probe(
                                        PROBE_RESPONSE,
                                        &info.nonce,
                                        &session_hash,
                                    );
                                    let _ = socket.send_to(&response, from_addr).await;
                                    let _ = tx.send(from_addr);
                                }
                                PROBE_RESPONSE => {
                                    tracing::info!(
                                        "Birthday #{}: RESPONSE from {} -- discovery!",
                                        index, from_addr
                                    );
                                    let _ = tx.send(from_addr);
                                }
                                _ => {}
                            }
                        }
                    }
                    Err(ref e) if e.raw_os_error() == Some(10054) => {
                        continue; // WSAECONNRESET on Windows
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        continue;
                    }
                    Err(_) => {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                }
            }
        }
    }
}

/// Spawn birthday socket tasks for parallel hole punching.
///
/// Creates temporary UDP sockets, each probing all target addresses at
/// `BIRTHDAY_PROBE_INTERVAL`. Discoveries are reported through `tx`.
fn spawn_birthday_sockets(
    targets: Vec<SocketAddr>,
    session_hash: [u8; 4],
    tx: mpsc::UnboundedSender<SocketAddr>,
) -> BirthdayGuard {
    let has_v4 = targets.iter().any(|a| a.is_ipv4());
    let has_v6 = targets.iter().any(|a| a.is_ipv6());

    let v4_count = if has_v4 { BIRTHDAY_SOCKET_COUNT } else { 0 };
    let v6_count = if has_v6 { BIRTHDAY_SOCKET_COUNT / 4 } else { 0 }; // IPv6 symmetric is rare
    let mut desired = v4_count + v6_count;

    // M6: Enforce global limit to prevent resource exhaustion
    let current = GLOBAL_BIRTHDAY_SOCKETS.load(Ordering::Relaxed);
    if current + desired > MAX_GLOBAL_BIRTHDAY_SOCKETS {
        desired = MAX_GLOBAL_BIRTHDAY_SOCKETS.saturating_sub(current);
        tracing::warn!(
            "Birthday socket limit: requested {} but global has {} (max={}), capping to {}",
            v4_count + v6_count, current, MAX_GLOBAL_BIRTHDAY_SOCKETS, desired
        );
    }
    if desired == 0 {
        tracing::warn!("Birthday sockets exhausted (global={}/{})", current, MAX_GLOBAL_BIRTHDAY_SOCKETS);
        return BirthdayGuard { handles: Vec::new(), socket_count: 0 };
    }

    let mut handles = Vec::with_capacity(desired);
    let mut actual_count: usize = 0;

    for i in 0..desired {
        let is_v6 = i >= v4_count;

        let std_socket = if is_v6 {
            match crate::dual_stack::create_raw_v6_socket() {
                Ok(s) => s,
                Err(_) => continue,
            }
        } else {
            match crate::dual_stack::create_raw_v4_socket() {
                Ok(s) => s,
                Err(_) => continue,
            }
        };

        let tokio_socket = match tokio::net::UdpSocket::from_std(std_socket) {
            Ok(s) => Arc::new(s),
            Err(_) => continue,
        };

        actual_count += 1;

        let tx = tx.clone();
        let targets = targets.clone();

        let handle = tokio::spawn(async move {
            // Stagger start to avoid burst
            tokio::time::sleep(Duration::from_millis(i as u64 * 3)).await;
            birthday_socket_task(i, tokio_socket, targets, session_hash, tx).await;
        });

        handles.push(handle);
    }

    GLOBAL_BIRTHDAY_SOCKETS.fetch_add(actual_count, Ordering::Relaxed);

    tracing::info!(
        "Birthday attack: spawned {} sockets (v4={}, v6={}) probing {} targets (global={})",
        handles.len(), v4_count.min(desired), v6_count.min(desired.saturating_sub(v4_count)),
        targets.len(), GLOBAL_BIRTHDAY_SOCKETS.load(Ordering::Relaxed),
    );

    BirthdayGuard { handles, socket_count: actual_count }
}

/// Run the hole punching process with aggressive burst probing.
///
/// Key techniques for high success rate:
///
/// 1. **Burst mode**: Sends probes to ALL remote candidates every tick (not
///    round-robin). This dramatically increases the chance of catching a NAT
///    pinhole opening since both sides probe simultaneously.
///
/// 2. **Fast interval**: 25ms between bursts. With N candidates, we send
///    N probes every 25ms = 40 bursts/second. Each candidate gets 40 probes/sec
///    regardless of how many candidates exist.
///
/// 3. **Immediate response**: When we receive a probe request, we respond
///    instantly. This opens our NAT in the reverse direction.
///
/// 4. **Bidirectional confirmation**: A probe response confirms the path works
///    both ways (our probe reached them AND their response reached us).
///
/// 5. **Fallback**: If we only receive requests but no responses (their NAT
///    allows us to receive but our responses get dropped), we use the source
///    address of the first received probe as a fallback path.
///
/// 6. **Multiple nonces**: We send a different nonce each burst cycle. This
///    helps distinguish fresh probes from delayed retransmissions.
///
/// 7. **Multi-round retry**: The total timeout is split into rounds (e.g., 3×5s).
///    Earlier rounds warm up NAT mapping tables on both sides, making later
///    rounds much more likely to succeed.
///
/// 8. **Port prediction**: When symmetric NAT is detected (multiple srflx
///    candidates with different ports from the same IP), predicts additional
///    target ports using the observed allocation delta.
///
/// 9. **Birthday attack**: When symmetric NAT is detected, opens 64+ temporary
///    UDP sockets that each get a different NAT mapping. This dramatically
///    increases the probability of a port collision with the remote NAT.
pub async fn run_hole_punch(
    socket: Arc<DualStackSocket>,
    remote_candidates: Vec<Candidate>,
    session_id: &str,
    timeout: Duration,
    mut probe_rx: mpsc::UnboundedReceiver<(Vec<u8>, SocketAddr)>,
    mut new_candidate_rx: mpsc::UnboundedReceiver<Candidate>,
) -> Result<PunchResult, String> {
    if remote_candidates.is_empty() {
        return Err("No remote candidates to punch".to_string());
    }

    let session_hash = compute_session_hash(session_id);
    let absolute_deadline = Instant::now() + timeout;

    // Multi-round configuration: split total timeout into rounds.
    // Earlier rounds warm up NAT mappings for later rounds.
    const MAX_ROUNDS: u32 = 3;
    let round_duration = timeout / MAX_ROUNDS;

    // Collect candidates into a mutable list; new ones can arrive dynamically
    let mut sorted_candidates = remote_candidates.clone();
    sorted_candidates.sort_by(|a, b| b.priority.cmp(&a.priority));

    // Track known addresses to avoid duplicate candidates
    let mut known_addrs: HashSet<SocketAddr> = sorted_candidates.iter().map(|c| c.address).collect();

    // Port prediction for symmetric NAT
    let mut predicted_targets: Vec<SocketAddr> = Vec::new();
    let mut analyzed_ips: HashSet<IpAddr> = HashSet::new();
    let initial_preds = generate_port_predictions(&sorted_candidates, &mut analyzed_ips);
    if !initial_preds.is_empty() {
        predicted_targets.extend(initial_preds);
    }

    // Birthday attack: multi-socket parallel probing for symmetric NAT
    let (birthday_tx, mut birthday_rx) = mpsc::unbounded_channel::<SocketAddr>();
    let mut _birthday_guard: Option<BirthdayGuard> = None;

    if is_symmetric_nat(&sorted_candidates) || !predicted_targets.is_empty() {
        let all_targets: Vec<SocketAddr> = sorted_candidates.iter().map(|c| c.address)
            .chain(predicted_targets.iter().copied())
            .collect();
        _birthday_guard = Some(spawn_birthday_sockets(all_targets, session_hash, birthday_tx.clone()));
    }

    // Burst mode: send to ALL candidates every 25ms
    let send_interval = Duration::from_millis(25);
    let mut send_timer = tokio::time::interval(send_interval);
    let mut total_probes_sent: u32 = 0;

    tracing::info!(
        "Starting hole punch: {} candidates, {} rounds × {:?}, total timeout {:?}",
        sorted_candidates.len(),
        MAX_ROUNDS,
        round_duration,
        timeout,
    );
    for (i, c) in sorted_candidates.iter().enumerate() {
        tracing::info!(
            "  Candidate #{}: {:?} {} (priority={})",
            i, c.candidate_type, c.address, c.priority
        );
    }

    for current_round in 1..=MAX_ROUNDS {
        let round_deadline = (Instant::now() + round_duration).min(absolute_deadline);

        // Per-round state
        let mut received_from: HashSet<SocketAddr> = HashSet::new();
        let mut first_received_addr: Option<SocketAddr> = None;
        let fallback_delay = Duration::from_millis(150);
        let mut fallback_deadline: Option<Instant> = None;
        let mut round_probes: u32 = 0;
        let mut burst_count: u32 = 0;

        if current_round > 1 {
            tracing::info!(
                "Punch round {}/{}: retrying with {} candidates ({} predicted), NAT mappings warmed up",
                current_round,
                MAX_ROUNDS,
                sorted_candidates.len(),
                predicted_targets.len(),
            );
        }

        loop {
            // Check deadlines
            let effective_deadline = match fallback_deadline {
                Some(fb) => fb.min(round_deadline),
                None => round_deadline,
            };

            if Instant::now() >= effective_deadline {
                // Fallback: use address that sent us a REQUEST
                if let Some(addr) = first_received_addr {
                    tracing::info!(
                        "Punch round {}: using fallback addr {} (REQUEST but no RESPONSE within {:?})",
                        current_round, addr,
                        if fallback_deadline.is_some() { fallback_delay } else { round_duration }
                    );
                    return Ok(PunchResult { remote_addr: addr });
                }
                // Round deadline reached with no progress
                if Instant::now() >= round_deadline {
                    total_probes_sent += round_probes;
                    if current_round < MAX_ROUNDS && Instant::now() < absolute_deadline {
                        tracing::info!(
                            "Punch round {}/{} timed out ({} probes in {} bursts), starting next round",
                            current_round, MAX_ROUNDS, round_probes, burst_count,
                        );
                        break; // Break inner loop, continue to next round
                    }
                    // Final round failed
                    return Err(format!(
                        "Hole punch timed out after {:?} ({} rounds, {} total probes, {} candidates)",
                        timeout, current_round, total_probes_sent + round_probes,
                        sorted_candidates.len() + predicted_targets.len(),
                    ));
                }
            }

            let remaining = effective_deadline.saturating_duration_since(Instant::now());

            tokio::select! {
                // BURST: send probes to ALL targets every tick
                _ = send_timer.tick() => {
                    let mut nonce = [0u8; 8];
                    use rand::RngCore;
                    rand::thread_rng().fill_bytes(&mut nonce);
                    let probe_req = build_probe(PROBE_REQUEST, &nonce, &session_hash);

                    for candidate in &sorted_candidates {
                        let addr = candidate.address;
                        match socket.send_to(&probe_req, addr).await {
                            Ok(_) => {
                                tracing::trace!("Sent probe to {}", addr);
                            }
                            Err(e) => {
                                tracing::trace!("Probe send to {} failed: {}", addr, e);
                            }
                        }
                    }
                    for &addr in &predicted_targets {
                        let _ = socket.send_to(&probe_req, addr).await;
                    }
                    round_probes += (sorted_candidates.len() + predicted_targets.len()) as u32;
                    burst_count += 1;
                }

                // Dynamically receive new candidates
                new_candidate = new_candidate_rx.recv() => {
                    if let Some(candidate) = new_candidate {
                        if known_addrs.insert(candidate.address) {
                            tracing::info!(
                                "Punch: adding late candidate {:?} {} (priority={})",
                                candidate.candidate_type, candidate.address, candidate.priority
                            );
                            sorted_candidates.push(candidate);
                            sorted_candidates.sort_by(|a, b| b.priority.cmp(&a.priority));

                            let new_preds = generate_port_predictions(&sorted_candidates, &mut analyzed_ips);
                            if !new_preds.is_empty() {
                                predicted_targets.extend(new_preds);
                            }

                            // Late birthday activation when symmetric NAT detected from trickled candidates
                            if _birthday_guard.is_none()
                                && (is_symmetric_nat(&sorted_candidates) || !predicted_targets.is_empty())
                            {
                                let all_targets: Vec<SocketAddr> = sorted_candidates.iter().map(|c| c.address)
                                    .chain(predicted_targets.iter().copied())
                                    .collect();
                                _birthday_guard = Some(spawn_birthday_sockets(
                                    all_targets, session_hash, birthday_tx.clone(),
                                ));
                            }
                        }
                    }
                }

                // Receive probes from remote peer
                msg = probe_rx.recv() => {
                    match msg {
                        Some((data, from_addr)) => {
                            if let Some(info) = parse_probe(&data) {
                                if info.session_hash != session_hash {
                                    tracing::trace!(
                                        "Ignoring probe from {} (session hash mismatch)",
                                        from_addr
                                    );
                                    continue;
                                }

                                match info.probe_type {
                                    PROBE_REQUEST => {
                                        let response = build_probe(
                                            PROBE_RESPONSE,
                                            &info.nonce,
                                            &session_hash,
                                        );
                                        let _ = socket.send_to(&response, from_addr).await;

                                        if received_from.insert(from_addr) {
                                            tracing::info!(
                                                "Received probe REQUEST from {} (responding)",
                                                from_addr
                                            );
                                        }

                                        // Peer Reflexive: if this address is not in our
                                        // known candidate list, the remote peer's NAT has
                                        // assigned a new mapping. Add it as a prflx
                                        // candidate so we actively probe it too.
                                        if !known_addrs.contains(&from_addr) {
                                            known_addrs.insert(from_addr);
                                            let prflx = Candidate::peer_reflexive(from_addr);
                                            tracing::info!(
                                                "Discovered peer-reflexive candidate: {} (priority={})",
                                                from_addr, prflx.priority
                                            );
                                            sorted_candidates.push(prflx);
                                            sorted_candidates.sort_by(|a, b| b.priority.cmp(&a.priority));
                                        }

                                        if first_received_addr.is_none() {
                                            first_received_addr = Some(from_addr);
                                            fallback_deadline = Some(Instant::now() + fallback_delay);
                                            tracing::info!(
                                                "Punch round {}: REQUEST received, starting {}ms fallback timer",
                                                current_round,
                                                fallback_delay.as_millis()
                                            );

                                            // Focused burst: send 3 REQUESTs immediately to
                                            // this address. Creates a fresh NAT mapping for
                                            // this specific target, increasing the chance of
                                            // getting a RESPONSE before the fallback timer.
                                            for _ in 0..3 {
                                                let mut burst_nonce = [0u8; 8];
                                                use rand::RngCore;
                                                rand::thread_rng().fill_bytes(&mut burst_nonce);
                                                let burst_req = build_probe(
                                                    PROBE_REQUEST,
                                                    &burst_nonce,
                                                    &session_hash,
                                                );
                                                let _ = socket.send_to(&burst_req, from_addr).await;
                                            }
                                        }
                                    }
                                    PROBE_RESPONSE => {
                                        tracing::info!(
                                            "Hole punch SUCCESS (round {}): bidirectional path to {}",
                                            current_round,
                                            from_addr
                                        );
                                        // Drain pending REQUESTs and respond
                                        while let Ok((pending_data, pending_addr)) = probe_rx.try_recv() {
                                            if let Some(pending_info) = parse_probe(&pending_data) {
                                                if pending_info.session_hash == session_hash
                                                    && pending_info.probe_type == PROBE_REQUEST
                                                {
                                                    let resp = build_probe(
                                                        PROBE_RESPONSE,
                                                        &pending_info.nonce,
                                                        &session_hash,
                                                    );
                                                    let _ = socket.send_to(&resp, pending_addr).await;
                                                }
                                            }
                                        }
                                        // Extra responses to all known REQUEST senders
                                        {
                                            let mut nonce = [0u8; 8];
                                            use rand::RngCore;
                                            rand::thread_rng().fill_bytes(&mut nonce);
                                            let extra_resp = build_probe(
                                                PROBE_RESPONSE,
                                                &nonce,
                                                &session_hash,
                                            );
                                            for &addr in &received_from {
                                                let _ = socket.send_to(&extra_resp, addr).await;
                                            }
                                        }
                                        return Ok(PunchResult {
                                            remote_addr: from_addr,
                                        });
                                    }
                                    _ => {
                                        tracing::trace!(
                                            "Unknown probe type {} from {}",
                                            info.probe_type,
                                            from_addr
                                        );
                                    }
                                }
                            }
                        }
                        None => {
                            return Err("Probe channel closed".to_string());
                        }
                    }
                }

                // Timeout guard
                _ = tokio::time::sleep(remaining) => {
                    if let Some(addr) = first_received_addr {
                        tracing::info!(
                            "Punch round {}: fallback to {} (REQUEST but no RESPONSE)",
                            current_round, addr
                        );
                        return Ok(PunchResult { remote_addr: addr });
                    }
                    if Instant::now() >= round_deadline {
                        total_probes_sent += round_probes;
                        if current_round < MAX_ROUNDS && Instant::now() < absolute_deadline {
                            tracing::info!(
                                "Punch round {}/{} timed out, starting next round",
                                current_round, MAX_ROUNDS,
                            );
                            break; // Next round
                        }
                        return Err(format!(
                            "Hole punch timed out after {:?} ({} rounds, {} total probes)",
                            timeout, current_round, total_probes_sent + round_probes,
                        ));
                    }
                }

                // Birthday attack: receive discoveries from multi-socket probing
                discovery = birthday_rx.recv() => {
                    if let Some(remote_addr) = discovery {
                        // Add as peer-reflexive candidate
                        if !known_addrs.contains(&remote_addr) {
                            known_addrs.insert(remote_addr);
                            let prflx = Candidate::peer_reflexive(remote_addr);
                            tracing::info!(
                                "Birthday discovery: peer-reflexive {} (priority={})",
                                remote_addr, prflx.priority
                            );
                            sorted_candidates.push(prflx);
                            sorted_candidates.sort_by(|a, b| b.priority.cmp(&a.priority));
                        }

                        // Send immediate probe from main socket while NAT pinhole is open
                        {
                            let mut nonce = [0u8; 8];
                            use rand::RngCore;
                            rand::thread_rng().fill_bytes(&mut nonce);
                            let probe_req = build_probe(PROBE_REQUEST, &nonce, &session_hash);
                            let _ = socket.send_to(&probe_req, remote_addr).await;
                        }

                        // Update fallback state
                        if received_from.insert(remote_addr) {
                            if first_received_addr.is_none() {
                                first_received_addr = Some(remote_addr);
                                fallback_deadline = Some(Instant::now() + fallback_delay);
                                tracing::info!(
                                    "Punch round {}: birthday discovery, starting {}ms fallback timer",
                                    current_round,
                                    fallback_delay.as_millis()
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    Err(format!(
        "Hole punch timed out after {:?} ({} rounds, {} total probes)",
        timeout, MAX_ROUNDS, total_probes_sent,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_probe_build_parse() {
        let nonce = [1, 2, 3, 4, 5, 6, 7, 8];
        let session_hash = compute_session_hash("test-session-123");
        let packet = build_probe(PROBE_REQUEST, &nonce, &session_hash);

        assert!(is_punch_probe(&packet));
        let info = parse_probe(&packet).unwrap();
        assert_eq!(info.probe_type, PROBE_REQUEST);
        assert_eq!(info.nonce, nonce);
        assert_eq!(info.session_hash, session_hash);
    }

    #[test]
    fn test_not_probe() {
        assert!(!is_punch_probe(&[0; 4]));
        assert!(!is_punch_probe(&[0; 17]));
        assert!(!is_punch_probe(&[]));
    }

    #[test]
    fn test_session_hash_consistency() {
        let h1 = compute_session_hash("session-abc");
        let h2 = compute_session_hash("session-abc");
        assert_eq!(h1, h2);

        let h3 = compute_session_hash("session-def");
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_derive_conv_id() {
        let c1 = derive_conv_id("session-abc");
        let c2 = derive_conv_id("session-abc");
        assert_eq!(c1, c2);
        assert_ne!(c1, 0);

        let c3 = derive_conv_id("session-def");
        assert_ne!(c1, c3);
    }

    #[test]
    fn test_probe_response() {
        let nonce = [10, 20, 30, 40, 50, 60, 70, 80];
        let session_hash = compute_session_hash("test-session");

        let request = build_probe(PROBE_REQUEST, &nonce, &session_hash);
        let response = build_probe(PROBE_RESPONSE, &nonce, &session_hash);

        let req_info = parse_probe(&request).unwrap();
        let resp_info = parse_probe(&response).unwrap();

        assert_eq!(req_info.probe_type, PROBE_REQUEST);
        assert_eq!(resp_info.probe_type, PROBE_RESPONSE);
        assert_eq!(req_info.nonce, resp_info.nonce);
        assert_eq!(req_info.session_hash, resp_info.session_hash);
    }

    #[test]
    fn test_port_prediction_symmetric_nat() {
        use crate::candidate::Candidate;

        // Simulate symmetric NAT: same IP, different ports from different STUN servers
        let candidates = vec![
            Candidate::server_reflexive("1.2.3.4:30000".parse().unwrap()),
            Candidate::server_reflexive("1.2.3.4:30002".parse().unwrap()),
            Candidate::server_reflexive("1.2.3.4:30004".parse().unwrap()),
        ];

        let mut analyzed = HashSet::new();
        let predictions = generate_port_predictions(&candidates, &mut analyzed);

        // Should detect delta=2 and generate predictions
        assert!(!predictions.is_empty());
        assert!(analyzed.contains(&"1.2.3.4".parse::<IpAddr>().unwrap()));

        // First forward prediction should be 30006
        assert_eq!(predictions[0], "1.2.3.4:30006".parse::<SocketAddr>().unwrap());
        // Second should be 30008
        assert_eq!(predictions[1], "1.2.3.4:30008".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn test_port_prediction_cone_nat_no_prediction() {
        use crate::candidate::Candidate;

        // Cone NAT: same address from all STUN servers (dedup leaves 1)
        let candidates = vec![
            Candidate::server_reflexive("1.2.3.4:30000".parse().unwrap()),
            Candidate::host("192.168.1.1:5000".parse().unwrap()),
        ];

        let mut analyzed = HashSet::new();
        let predictions = generate_port_predictions(&candidates, &mut analyzed);

        // Should NOT generate predictions (only 1 srflx port)
        assert!(predictions.is_empty());
    }

    #[test]
    fn test_is_symmetric_nat_detected() {
        use crate::candidate::Candidate;

        // Two srflx from same IP with different ports → symmetric
        let candidates = vec![
            Candidate::server_reflexive("1.2.3.4:30000".parse().unwrap()),
            Candidate::server_reflexive("1.2.3.4:30002".parse().unwrap()),
        ];
        assert!(is_symmetric_nat(&candidates));

        // Only one srflx → not symmetric
        let candidates = vec![
            Candidate::server_reflexive("1.2.3.4:30000".parse().unwrap()),
            Candidate::host("192.168.1.1:5000".parse().unwrap()),
        ];
        assert!(!is_symmetric_nat(&candidates));

        // No srflx at all → not symmetric
        let candidates = vec![
            Candidate::host("192.168.1.1:5000".parse().unwrap()),
        ];
        assert!(!is_symmetric_nat(&candidates));

        // Different IPs → not symmetric (each IP has only 1 port)
        let candidates = vec![
            Candidate::server_reflexive("1.2.3.4:30000".parse().unwrap()),
            Candidate::server_reflexive("5.6.7.8:40000".parse().unwrap()),
        ];
        assert!(!is_symmetric_nat(&candidates));
    }
}
