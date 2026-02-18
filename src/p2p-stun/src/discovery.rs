use std::net::SocketAddr;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DiscoveryError {
    #[error("STUN error: {0}")]
    Stun(#[from] crate::binding::StunError),
    #[error("NAT detection requires a STUN server with two IP addresses (RFC 5780)")]
    UnsupportedServer,
}

/// NAT mapping behavior per RFC 5780 Section 4.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MappingBehavior {
    /// Same mapping regardless of destination. Best case for hole punching.
    EndpointIndependent,
    /// Mapping changes per destination IP.
    AddressDependent,
    /// Mapping changes per destination IP:port. Worst case.
    AddressAndPortDependent,
}

/// NAT filtering behavior per RFC 5780 Section 4.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilteringBehavior {
    /// Accepts packets from any source.
    EndpointIndependent,
    /// Accepts packets only from contacted IPs.
    AddressDependent,
    /// Accepts packets only from exact contacted IP:port.
    AddressAndPortDependent,
}

/// NAT information discovered via STUN.
#[derive(Debug, Clone)]
pub struct NatInfo {
    pub mapping: MappingBehavior,
    pub filtering: FilteringBehavior,
    pub external_addr_v4: Option<SocketAddr>,
    pub external_addr_v6: Option<SocketAddr>,
}

impl NatInfo {
    /// Predict whether direct hole punching can succeed between two NAT types.
    pub fn can_punch(initiator: &MappingBehavior, responder: &MappingBehavior) -> bool {
        match (initiator, responder) {
            (MappingBehavior::EndpointIndependent, _) => true,
            (_, MappingBehavior::EndpointIndependent) => true,
            (MappingBehavior::AddressDependent, MappingBehavior::AddressDependent) => true,
            _ => false,
        }
    }
}

// Full RFC 5780 NAT behavior discovery will be implemented when we have
// access to a STUN server with dual IP support. For now, the basic
// STUN binding in binding.rs provides the server-reflexive address,
// and we attempt hole punching on all candidate pairs regardless of NAT type.
