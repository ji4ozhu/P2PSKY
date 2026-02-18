use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;

use crate::error::P2pError;

/// Dual-stack UDP socket manager.
///
/// Uses two independent sockets (one IPv4, one IPv6) instead of a single
/// dual-stack socket to avoid platform-specific `IPV6_V6ONLY` behavior
/// differences across Windows, macOS, Linux, iOS, and Android.
pub struct DualStackSocket {
    v4: Option<Arc<UdpSocket>>,
    v6: Option<Arc<UdpSocket>>,
    v4_port: u16,
    v6_port: u16,
}

impl DualStackSocket {
    /// Bind dual-stack sockets. Tries to use the same port for both.
    /// If `enable_ipv6` is false, only binds the IPv4 socket.
    pub async fn bind(port: u16, enable_ipv6: bool) -> Result<Self, P2pError> {
        let v4_socket = Self::create_v4_socket(port)?;
        let v4_port = v4_socket.local_addr()?.port();
        let v4 = Some(Arc::new(UdpSocket::from_std(v4_socket)?));

        let (v6, v6_port) = if enable_ipv6 {
            match Self::create_v6_socket(v4_port) {
                Ok(s) => {
                    let port = s.local_addr()?.port();
                    (Some(Arc::new(UdpSocket::from_std(s)?)), port)
                }
                Err(e) => {
                    tracing::warn!("IPv6 socket creation failed (IPv4-only mode): {}", e);
                    (None, 0)
                }
            }
        } else {
            (None, 0)
        };

        tracing::info!(
            "DualStack bound: v4=0.0.0.0:{}, v6={}",
            v4_port,
            if v6.is_some() {
                format!("[::]:{}", v6_port)
            } else {
                "disabled".to_string()
            }
        );

        Ok(Self {
            v4,
            v6,
            v4_port,
            v6_port,
        })
    }

    /// Send data to the given address, automatically selecting the right socket.
    pub async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> Result<usize, P2pError> {
        match addr {
            SocketAddr::V4(_) => {
                let socket = self.v4.as_ref().ok_or_else(|| {
                    P2pError::Io(std::io::Error::new(
                        std::io::ErrorKind::AddrNotAvailable,
                        "No IPv4 socket",
                    ))
                })?;
                Ok(socket.send_to(buf, addr).await?)
            }
            SocketAddr::V6(_) => {
                let socket = self.v6.as_ref().ok_or_else(|| {
                    P2pError::Io(std::io::Error::new(
                        std::io::ErrorKind::AddrNotAvailable,
                        "No IPv6 socket (IPv6 disabled)",
                    ))
                })?;
                Ok(socket.send_to(buf, addr).await?)
            }
        }
    }

    /// Receive from either socket, returning the data and source address.
    /// Uses `tokio::select!` in a loop to wait on whichever socket receives first.
    ///
    /// On spurious wakeups (WouldBlock) or WSAECONNRESET (10054, common during
    /// hole punching on Windows), we loop back to `select!` on BOTH sockets.
    /// This prevents the recv loop from getting stuck waiting on one socket
    /// while data arrives on the other.
    pub async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), P2pError> {
        match (&self.v4, &self.v6) {
            (Some(v4), Some(v6)) => {
                loop {
                    tokio::select! {
                        _ = v4.readable() => {
                            match v4.try_recv_from(buf) {
                                Ok(result) => return Ok(result),
                                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                    continue; // spurious wakeup, re-enter select!
                                }
                                Err(ref e) if e.raw_os_error() == Some(10054) => {
                                    continue; // WSAECONNRESET, re-enter select!
                                }
                                Err(e) => return Err(P2pError::Io(e)),
                            }
                        }
                        _ = v6.readable() => {
                            match v6.try_recv_from(buf) {
                                Ok(result) => return Ok(result),
                                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                    continue; // spurious wakeup, re-enter select!
                                }
                                Err(ref e) if e.raw_os_error() == Some(10054) => {
                                    continue; // WSAECONNRESET, re-enter select!
                                }
                                Err(e) => return Err(P2pError::Io(e)),
                            }
                        }
                    }
                }
            }
            (Some(v4), None) => Ok(v4.recv_from(buf).await?),
            (None, Some(v6)) => Ok(v6.recv_from(buf).await?),
            (None, None) => Err(P2pError::Io(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "No sockets available",
            ))),
        }
    }

    /// Get the IPv4 socket (if available).
    pub fn v4_socket(&self) -> Option<&Arc<UdpSocket>> {
        self.v4.as_ref()
    }

    /// Get the IPv6 socket (if available).
    pub fn v6_socket(&self) -> Option<&Arc<UdpSocket>> {
        self.v6.as_ref()
    }

    /// Get the IPv4 port.
    pub fn v4_port(&self) -> u16 {
        self.v4_port
    }

    /// Get the IPv6 port.
    pub fn v6_port(&self) -> u16 {
        self.v6_port
    }

    pub(crate) fn create_v4_socket(port: u16) -> Result<std::net::UdpSocket, P2pError> {
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        socket.set_reuse_address(true)?;
        #[cfg(not(target_os = "windows"))]
        {
            socket.set_reuse_port(true)?;
        }
        socket.set_nonblocking(true)?;
        Self::disable_connreset(&socket);
        let addr: SocketAddr = format!("0.0.0.0:{}", port).parse().unwrap();
        socket.bind(&addr.into())?;
        Ok(socket.into())
    }

    pub(crate) fn create_v6_socket(port: u16) -> Result<std::net::UdpSocket, P2pError> {
        let socket = socket2::Socket::new(
            socket2::Domain::IPV6,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        socket.set_only_v6(true)?; // Strict IPv6 only, no mapped IPv4
        socket.set_reuse_address(true)?;
        #[cfg(not(target_os = "windows"))]
        {
            socket.set_reuse_port(true)?;
        }
        socket.set_nonblocking(true)?;
        Self::disable_connreset(&socket);
        let addr: SocketAddr = format!("[::0]:{}", port).parse().unwrap();
        socket.bind(&addr.into())?;
        Ok(socket.into())
    }

    /// Disable Windows WSAECONNRESET (10054) on UDP sockets.
    ///
    /// On Windows, sending a UDP packet to an unreachable destination causes
    /// the OS to feed an ICMP "Port Unreachable" error back to the socket.
    /// The next recv_from() call then fails with WSAECONNRESET instead of
    /// returning actual data. This is catastrophic for hole punching because
    /// most probe targets are initially unreachable (that's the whole point).
    ///
    /// SIO_UDP_CONNRESET (0x9800000C) disables this behavior.
    #[cfg(target_os = "windows")]
    fn disable_connreset(socket: &socket2::Socket) {
        use std::os::windows::io::AsRawSocket;
        const SIO_UDP_CONNRESET: u32 = 0x9800000C;

        extern "system" {
            fn WSAIoctl(
                s: usize,
                dwIoControlCode: u32,
                lpvInBuffer: *mut std::ffi::c_void,
                cbInBuffer: u32,
                lpvOutBuffer: *mut std::ffi::c_void,
                cbOutBuffer: u32,
                lpcbBytesReturned: *mut u32,
                lpOverlapped: *mut std::ffi::c_void,
                lpCompletionRoutine: *mut std::ffi::c_void,
            ) -> i32;
        }

        let raw = socket.as_raw_socket() as usize;
        let mut enable: u32 = 0; // FALSE = disable CONNRESET
        let mut bytes_returned: u32 = 0;
        // L2: Check WSAIoctl return value and log on failure.
        let result = unsafe {
            WSAIoctl(
                raw,
                SIO_UDP_CONNRESET,
                &mut enable as *mut u32 as *mut std::ffi::c_void,
                std::mem::size_of::<u32>() as u32,
                std::ptr::null_mut(),
                0,
                &mut bytes_returned,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if result != 0 {
            tracing::warn!("WSAIoctl SIO_UDP_CONNRESET failed (error={})", result);
        }
    }

    #[cfg(not(target_os = "windows"))]
    fn disable_connreset(_socket: &socket2::Socket) {
        // No-op on non-Windows platforms
    }
}

/// Create a single IPv4 UDP socket bound to an OS-assigned random port.
/// Applies SO_REUSEADDR, non-blocking, and Windows CONNRESET fix.
pub fn create_raw_v4_socket() -> Result<std::net::UdpSocket, P2pError> {
    DualStackSocket::create_v4_socket(0)
}

/// Create a single IPv6 UDP socket bound to an OS-assigned random port.
/// Applies IPV6_V6ONLY, SO_REUSEADDR, non-blocking, and Windows CONNRESET fix.
pub fn create_raw_v6_socket() -> Result<std::net::UdpSocket, P2pError> {
    DualStackSocket::create_v6_socket(0)
}
