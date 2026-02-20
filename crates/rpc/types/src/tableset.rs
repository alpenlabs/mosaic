use mosaic_cac_proto_types::{CacRole, SetupWireInputs, TablesetInstanceId};
use mosaic_net_svc_api::PeerId;
use serde::{Deserialize, Serialize};

use crate::CacParams;

/// Configuration provided as part of setting up a game instance.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RpcSetupConfig {
    /// The name of the circuit we'll use.
    ///
    /// This matches the client configuration for where to find this circuit information.
    circuit_name: String,

    /// The role we're playing in the setup.
    role: CacRole,

    /// CaC game configuration.
    cac_params: CacParams,

    /// Peer connection information.
    peer_info: RpcPeerInfo,

    /// corresponds to operator pubkey
    setup_inputs: SetupWireInputs,

    /// For multiple tablesets per (garbler, evaluator) pair
    /// Both sides must use the same instance id.
    instance_id: TablesetInstanceId,
}

/// Describes information about the peer we're interacting with so we can
/// connect to them and authenticate messages.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RpcPeerInfo {
    // stable identifier to peer
    peer_id: PeerId,
    // TODO: more fields as required
}

/// Status of where a tableset during setup.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum RpcTablesetSetupStatus {
    /// Setup is incomplete.
    /// Wait for this to complete.
    Incomplete {
        /// Additional info like which step its in, or its specific status, etc.
        /// This is mainly for debugging
        details: String,
    },

    /// Setup is completed successfully.
    /// This setup can noew be used to process deposits.
    SetupComplete,

    /// Setup has been used for withdrawal dispute resolution.
    /// DO NOT USE THIS SETUP AGAIN.
    Consumed,

    /// Setup was aborted.
    /// NEW SETUP REQUIRED.
    Aborted {
        /// Reason for aborting.
        /// This is mainly for debugging.
        reason: String,
    },
}
