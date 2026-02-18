use std::net::SocketAddr;
use std::time::Duration;
use thiserror::Error;
use tokio::net::UdpSocket;

use crate::router::StunResponseRouter;

#[derive(Error, Debug)]
pub enum StunError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("STUN request timed out")]
    Timeout,
    #[error("Invalid STUN response")]
    InvalidResponse,
    #[error("No XOR-MAPPED-ADDRESS in response")]
    NoMappedAddress,
}

/// STUN Binding request/response client.
///
/// Sends STUN Binding requests to discover the server-reflexive (public)
/// address as seen by the STUN server.
pub struct StunClient {
    timeout: std::time::Duration,
}

/// STUN message constants
const STUN_MAGIC_COOKIE: u32 = 0x2112A442;
const STUN_BINDING_REQUEST: u16 = 0x0001;
const STUN_BINDING_RESPONSE: u16 = 0x0101;
const STUN_HEADER_SIZE: usize = 20;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;

impl StunClient {
    pub fn new(timeout: std::time::Duration) -> Self {
        Self { timeout }
    }

    /// Send a STUN Binding request and return the mapped (public) address.
    ///
    /// WARNING: This method reads directly from the socket. If a central recv loop
    /// is also reading from the same socket, use `binding_request_routed()` instead.
    pub async fn binding_request(
        &self,
        socket: &UdpSocket,
        server_addr: SocketAddr,
    ) -> Result<SocketAddr, StunError> {
        let transaction_id = Self::generate_transaction_id();
        let request = Self::build_binding_request(&transaction_id);

        socket.send_to(&request, server_addr).await?;

        let mut buf = [0u8; 576];
        let result = tokio::time::timeout(self.timeout, socket.recv_from(&mut buf)).await;

        match result {
            Ok(Ok((len, _from))) => {
                let data = &buf[..len];
                Self::parse_binding_response(data, &transaction_id)
            }
            Ok(Err(e)) => Err(StunError::Io(e)),
            Err(_) => Err(StunError::Timeout),
        }
    }

    /// Send a STUN Binding request using a shared socket with centralized recv loop.
    ///
    /// This version works correctly when a central recv loop reads from the socket
    /// and routes STUN responses via `StunResponseRouter::try_route()`.
    ///
    /// Retries up to 3 times with exponential backoff (500ms → 1s → 2s).
    pub async fn binding_request_routed(
        &self,
        socket: &UdpSocket,
        server_addr: SocketAddr,
        router: &StunResponseRouter,
    ) -> Result<SocketAddr, StunError> {
        for attempt in 0..3u32 {
            let transaction_id = Self::generate_transaction_id();
            let request = Self::build_binding_request(&transaction_id);

            // Register for response BEFORE sending to avoid race condition
            let rx = router.expect_response(transaction_id);

            if let Err(e) = socket.send_to(&request, server_addr).await {
                router.cancel(&transaction_id);
                return Err(StunError::Io(e));
            }

            // Exponential backoff: 500ms, 1000ms, 2000ms
            let timeout_ms = 500u64 * (1 << attempt);
            match tokio::time::timeout(Duration::from_millis(timeout_ms), rx).await {
                Ok(Ok(data)) => {
                    return Self::parse_binding_response(&data, &transaction_id);
                }
                _ => {
                    // Timeout or channel closed — clean up and retry
                    router.cancel(&transaction_id);
                    tracing::debug!(
                        "STUN binding to {} attempt {}/{} timed out",
                        server_addr,
                        attempt + 1,
                        3
                    );
                    continue;
                }
            }
        }
        Err(StunError::Timeout)
    }

    pub fn generate_transaction_id() -> [u8; 12] {
        let mut id = [0u8; 12];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut id);
        id
    }

    pub fn build_binding_request(transaction_id: &[u8; 12]) -> Vec<u8> {
        let mut msg = Vec::with_capacity(STUN_HEADER_SIZE);
        // Message Type: Binding Request (0x0001)
        msg.extend_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
        // Message Length: 0 (no attributes)
        msg.extend_from_slice(&0u16.to_be_bytes());
        // Magic Cookie
        msg.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        // Transaction ID (12 bytes)
        msg.extend_from_slice(transaction_id);
        msg
    }

    pub fn parse_binding_response(
        data: &[u8],
        expected_txn_id: &[u8; 12],
    ) -> Result<SocketAddr, StunError> {
        if data.len() < STUN_HEADER_SIZE {
            return Err(StunError::InvalidResponse);
        }

        // Check message type is Binding Response
        let msg_type = u16::from_be_bytes([data[0], data[1]]);
        if msg_type != STUN_BINDING_RESPONSE {
            return Err(StunError::InvalidResponse);
        }

        // Check magic cookie
        let cookie = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        if cookie != STUN_MAGIC_COOKIE {
            return Err(StunError::InvalidResponse);
        }

        // Check transaction ID
        if &data[8..20] != expected_txn_id {
            return Err(StunError::InvalidResponse);
        }

        let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
        if data.len() < STUN_HEADER_SIZE + msg_len {
            return Err(StunError::InvalidResponse);
        }

        // Parse attributes
        let mut offset = STUN_HEADER_SIZE;
        while offset + 4 <= STUN_HEADER_SIZE + msg_len {
            let attr_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let attr_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
            let attr_data_start = offset + 4;

            if attr_data_start + attr_len > data.len() {
                break;
            }

            let attr_data = &data[attr_data_start..attr_data_start + attr_len];

            if attr_type == ATTR_XOR_MAPPED_ADDRESS {
                return Self::parse_xor_mapped_address(attr_data, expected_txn_id);
            } else if attr_type == ATTR_MAPPED_ADDRESS {
                return Self::parse_mapped_address(attr_data);
            }

            // Attributes are padded to 4-byte boundary
            let padded_len = (attr_len + 3) & !3;
            offset = attr_data_start + padded_len;
        }

        Err(StunError::NoMappedAddress)
    }

    fn parse_xor_mapped_address(
        attr_data: &[u8],
        transaction_id: &[u8; 12],
    ) -> Result<SocketAddr, StunError> {
        if attr_data.len() < 4 {
            return Err(StunError::InvalidResponse);
        }
        let family = attr_data[1];
        let xor_port = u16::from_be_bytes([attr_data[2], attr_data[3]]);
        let port = xor_port ^ (STUN_MAGIC_COOKIE >> 16) as u16;

        match family {
            0x01 => {
                // IPv4
                if attr_data.len() < 8 {
                    return Err(StunError::InvalidResponse);
                }
                let xor_ip = u32::from_be_bytes([
                    attr_data[4],
                    attr_data[5],
                    attr_data[6],
                    attr_data[7],
                ]);
                let ip = xor_ip ^ STUN_MAGIC_COOKIE;
                let addr = std::net::Ipv4Addr::from(ip);
                Ok(SocketAddr::new(std::net::IpAddr::V4(addr), port))
            }
            0x02 => {
                // IPv6
                if attr_data.len() < 20 {
                    return Err(StunError::InvalidResponse);
                }
                let mut xor_ip = [0u8; 16];
                xor_ip.copy_from_slice(&attr_data[4..20]);
                // XOR with magic cookie (4 bytes) + transaction ID (12 bytes)
                let cookie_bytes = STUN_MAGIC_COOKIE.to_be_bytes();
                for i in 0..4 {
                    xor_ip[i] ^= cookie_bytes[i];
                }
                for i in 0..12 {
                    xor_ip[4 + i] ^= transaction_id[i];
                }
                let addr = std::net::Ipv6Addr::from(xor_ip);
                Ok(SocketAddr::new(std::net::IpAddr::V6(addr), port))
            }
            _ => Err(StunError::InvalidResponse),
        }
    }

    fn parse_mapped_address(attr_data: &[u8]) -> Result<SocketAddr, StunError> {
        if attr_data.len() < 4 {
            return Err(StunError::InvalidResponse);
        }
        let family = attr_data[1];
        let port = u16::from_be_bytes([attr_data[2], attr_data[3]]);

        match family {
            0x01 => {
                if attr_data.len() < 8 {
                    return Err(StunError::InvalidResponse);
                }
                let ip = std::net::Ipv4Addr::new(
                    attr_data[4],
                    attr_data[5],
                    attr_data[6],
                    attr_data[7],
                );
                Ok(SocketAddr::new(std::net::IpAddr::V4(ip), port))
            }
            0x02 => {
                if attr_data.len() < 20 {
                    return Err(StunError::InvalidResponse);
                }
                let mut ip_bytes = [0u8; 16];
                ip_bytes.copy_from_slice(&attr_data[4..20]);
                let ip = std::net::Ipv6Addr::from(ip_bytes);
                Ok(SocketAddr::new(std::net::IpAddr::V6(ip), port))
            }
            _ => Err(StunError::InvalidResponse),
        }
    }
}

/// Check if a packet is a STUN message by inspecting the magic cookie.
pub fn is_stun_message(data: &[u8]) -> bool {
    if data.len() < 8 {
        return false;
    }
    let cookie = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    cookie == STUN_MAGIC_COOKIE
}
