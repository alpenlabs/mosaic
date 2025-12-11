use mosaic_cac_proto_types::{CacConfig, CacRole};
use serde::{Deserialize, Serialize};

/// Configuration provided as part of setting up a game instance.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RpcGameInstanceConfig {
    /// The name of the circuit we'll use.
    ///
    /// This matches the client configuration for where to find this circuit information.
    circuit_name: String,

    /// The role we're playing in the setup.
    role: CacRole,

    /// CaC game configuration.
    cac_config: CacConfig,

    /// Peer connection information.
    peer_info: GamePeerInfo,
}

/// Describes information about the peer we're interacting with so we can
/// connect to them and authenticate messages.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GamePeerInfo {
    // TODO
}
