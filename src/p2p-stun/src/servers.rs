use std::net::SocketAddr;

/// A list of well-known public STUN servers.
pub struct StunServerList;

impl StunServerList {
    /// Returns a list of public STUN server addresses (IPv4).
    pub fn default_ipv4() -> Vec<&'static str> {
        vec![
            "stun.cloudflare.com:3478",
            "stun.l.google.com:19302",
            "stun.voip.blackberry.com:3478",
            "stun.sipnet.com:3478",
            "stun.f.haeder.net:3478",
        ]
    }

    /// Returns a list of public STUN server addresses (IPv6-capable).
    pub fn default_ipv6() -> Vec<&'static str> {
        vec![
            "stun.cloudflare.com:3478",
            "stun.l.google.com:19302",
        ]
    }

    /// Resolve a STUN server hostname to socket addresses.
    pub async fn resolve(server: &str) -> std::io::Result<Vec<SocketAddr>> {
        tokio::net::lookup_host(server)
            .await
            .map(|addrs| addrs.collect())
    }
}
