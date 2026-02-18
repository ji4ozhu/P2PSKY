use p2p_stun::discovery::MappingBehavior;

/// NAT type detection utilities.
///
/// Wraps the STUN-based NAT behavior discovery from p2p-stun.
/// For now, provides prediction logic for hole punching success.
/// Full RFC 5780 detection requires a STUN server with dual IP support.

/// Predict hole punching viability based on both peers' NAT types.
pub fn predict_punch_success(
    local_mapping: &MappingBehavior,
    remote_mapping: &MappingBehavior,
) -> PunchPrediction {
    match (local_mapping, remote_mapping) {
        (MappingBehavior::EndpointIndependent, _)
        | (_, MappingBehavior::EndpointIndependent) => PunchPrediction::Likely,

        (MappingBehavior::AddressDependent, MappingBehavior::AddressDependent) => {
            PunchPrediction::Possible
        }

        (MappingBehavior::AddressAndPortDependent, MappingBehavior::AddressAndPortDependent) => {
            PunchPrediction::Unlikely
        }

        _ => PunchPrediction::Possible,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PunchPrediction {
    /// Hole punching should succeed.
    Likely,
    /// Hole punching may succeed with simultaneous open.
    Possible,
    /// Hole punching will likely fail; TURN relay recommended.
    Unlikely,
}
