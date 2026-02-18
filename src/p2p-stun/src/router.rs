use std::collections::HashMap;
use parking_lot::Mutex;
use tokio::sync::oneshot;

/// Routes STUN/TURN responses from a central UDP receive loop to waiting callers.
///
/// Problem: When multiple components share the same UDP socket (hole punching,
/// STUN binding, TURN allocation), a single recv loop reads all incoming packets.
/// STUN binding requests and TURN allocations send requests through this socket
/// and need to receive the matching response.
///
/// Solution: Callers register interest in a specific STUN transaction ID before
/// sending the request. The recv loop calls `try_route()` on every STUN packet;
/// if it matches a pending transaction, the response is delivered via a oneshot channel.
///
/// This works for both STUN and TURN signaling messages since they share the
/// same STUN message format with a 12-byte transaction ID at bytes [8..20].
pub struct StunResponseRouter {
    // Using parking_lot::Mutex instead of std::sync::Mutex to avoid poison panic.
    // If a thread panics while holding a std::sync::Mutex, the mutex becomes
    // permanently poisoned and all subsequent lock() calls panic.
    pending: Mutex<HashMap<[u8; 12], oneshot::Sender<Vec<u8>>>>,
}

impl StunResponseRouter {
    pub fn new() -> Self {
        Self {
            pending: Mutex::new(HashMap::new()),
        }
    }

    /// Register interest in a STUN transaction response.
    /// Returns a receiver that will deliver the raw response bytes when they arrive.
    ///
    /// Must be called BEFORE sending the request to avoid race conditions.
    pub fn expect_response(&self, txn_id: [u8; 12]) -> oneshot::Receiver<Vec<u8>> {
        let (tx, rx) = oneshot::channel();
        self.pending.lock().insert(txn_id, tx);
        rx
    }

    /// Try to route an incoming STUN-formatted packet to a registered waiter.
    /// Returns `true` if the packet was consumed (matched a pending transaction).
    ///
    /// The packet must be a valid STUN message (magic cookie 0x2112A442 at bytes 4-7).
    /// The 12-byte transaction ID is extracted from bytes [8..20].
    pub fn try_route(&self, data: &[u8]) -> bool {
        if data.len() < 20 {
            return false;
        }

        // Verify STUN magic cookie
        let cookie = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        if cookie != 0x2112A442 {
            return false;
        }

        let mut txn_id = [0u8; 12];
        txn_id.copy_from_slice(&data[8..20]);

        let mut pending = self.pending.lock();
        if let Some(tx) = pending.remove(&txn_id) {
            let _ = tx.send(data.to_vec());
            true
        } else {
            false
        }
    }

    /// Cancel a pending transaction registration (e.g., after timeout before retry).
    pub fn cancel(&self, txn_id: &[u8; 12]) {
        self.pending.lock().remove(txn_id);
    }
}

impl Default for StunResponseRouter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_route_matching() {
        let router = StunResponseRouter::new();
        let txn_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

        let rx = router.expect_response(txn_id);

        // Build a fake STUN response with matching transaction ID
        let mut packet = vec![0u8; 20];
        // Magic cookie at bytes 4-7
        packet[4..8].copy_from_slice(&0x2112A442u32.to_be_bytes());
        // Transaction ID at bytes 8-20
        packet[8..20].copy_from_slice(&txn_id);

        assert!(router.try_route(&packet));
        let received = rx.await.unwrap();
        assert_eq!(received, packet);
    }

    #[test]
    fn test_route_no_match() {
        let router = StunResponseRouter::new();
        let txn_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let _rx = router.expect_response(txn_id);

        // Different transaction ID
        let mut packet = vec![0u8; 20];
        packet[4..8].copy_from_slice(&0x2112A442u32.to_be_bytes());
        packet[8..20].copy_from_slice(&[99; 12]);

        assert!(!router.try_route(&packet));
    }

    #[test]
    fn test_route_not_stun() {
        let router = StunResponseRouter::new();
        // Too short
        assert!(!router.try_route(&[0; 10]));
        // Wrong magic cookie
        assert!(!router.try_route(&[0; 20]));
    }

    #[test]
    fn test_cancel() {
        let router = StunResponseRouter::new();
        let txn_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let _rx = router.expect_response(txn_id);
        router.cancel(&txn_id);

        // Build matching packet — should NOT route since we cancelled
        let mut packet = vec![0u8; 20];
        packet[4..8].copy_from_slice(&0x2112A442u32.to_be_bytes());
        packet[8..20].copy_from_slice(&txn_id);
        assert!(!router.try_route(&packet));
    }
}
