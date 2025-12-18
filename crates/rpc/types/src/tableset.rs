use mosaic_cac_proto_types::CacRole;
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
    peer_info: GamePeerInfo,

    /// corresponds to operator pubkey
    setup_inputs: Vec<u8>,

    /// For multiple tablesets per (garbler, evaluator) pair
    /// Both sides must use the same instance id.
    instance_id: u64,
}

/// Describes information about the peer we're interacting with so we can
/// connect to them and authenticate messages.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GamePeerInfo {
    // stable identifier to peer
    peer_id: Vec<u8>, // TODO: more fields as required
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum RpcGarblerSetupStage {
    Init,
    GeneratedShares,
    GeneratedCommitments,
    WaitForChallenge,
    ReceivedChallenge,
    GenerateChallengeResponse,
    WaitForTableTransfer,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum RpcEvaluatorSetupStage {
    Init,
    ReceivedCommitment,
    OpeningsSampled,
    GeneratedChallenge,
    WaitForChallengeResponse,
    SharesVerified,
    VerifyingTableCommitments,
}

/// Details on which stage of the setup process we are at.
/// For debugging and observability.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum RpcIncompleteStatus {
    /// garbler statuses
    Garbler(RpcGarblerSetupStage),
    /// evaluator statuses
    Evaluator(RpcEvaluatorSetupStage),
}

/// Status of where a tableset during setup.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum RpcTablesetSetupStatus {
    /// setup incomplete
    Incomplete(RpcIncompleteStatus),

    /// setup is completed
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
