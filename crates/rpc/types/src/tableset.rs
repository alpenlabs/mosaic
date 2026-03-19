use mosaic_common::constants::{N_CIRCUITS, N_OPEN_CIRCUITS};
use serde::{Deserialize, Serialize};

use crate::{RpcDepositId, RpcInstanceId, RpcPeerId, RpcSetupInputs};

/// Info about a CaC game.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TablesetSetupInfo {
    circuit_name: String,
    role: CacRole,
    cac_params: CacParams,
    setup_inputs: RpcSetupInputs,
    instance: RpcInstanceId,
    peer: RpcPeerId,
}

/// The role the client should play in the garbling game.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CacRole {
    /// Garbler.
    Garbler,

    /// Evaluator.
    Evaluator,
}

/// Cac params that can be used to setup.
#[derive(Copy, Clone, Debug, Deserialize, Serialize)]
pub struct CacParams {
    tables: u64,
    selected_openings: u64,
}

impl CacParams {
    /// Total number of tables.
    pub fn tables(&self) -> u64 {
        self.tables
    }

    /// Number of openings during Cac.
    pub fn selected_openings(&self) -> u64 {
        self.selected_openings
    }
}

impl Default for CacParams {
    fn default() -> Self {
        Self {
            tables: N_CIRCUITS as u64,
            selected_openings: N_OPEN_CIRCUITS as u64,
        }
    }
}

/// Configuration provided as part of setting up a game instance.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RpcSetupConfig {
    /// The role we're playing in the setup.
    pub role: CacRole,

    /// Peer connection information.
    pub peer_info: RpcPeerInfo,

    /// corresponds to operator pubkey
    pub setup_inputs: RpcSetupInputs,

    /// For multiple tablesets per (garbler, evaluator) pair
    /// Both sides must use the same instance id.
    pub instance_id: RpcInstanceId,
}

/// Describes information about the peer we're interacting with so we can
/// connect to them and authenticate messages.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RpcPeerInfo {
    /// stable identifier to peer
    pub peer_id: RpcPeerId,
}

/// Status of where a tableset during setup.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum RpcTablesetStatus {
    /// Setup is incomplete.
    /// Wait for this to complete.
    Incomplete {
        /// Additional info like which step its in, or its specific status, etc.
        /// This is mainly for debugging
        details: String,
    },

    /// Setup is completed successfully.
    /// This setup can now be used to process deposits.
    SetupComplete,

    /// Setup is being used to resolve a contested withdrawal.
    /// For Garbler -> adaptor signatures are being completed
    /// For Evaluator -> garbling tables are being evaluated to extract final secret.
    ///
    /// CANNOT USE THIS SETUP AGAIN TO PROCESS DEPOSITS.
    Contest {
        /// Deposit for which contested withdrawal is occuring.
        deposit: RpcDepositId,
    },

    /// Setup has been used for contested withdrawal resolution. Mosaic side processing is
    /// completed.
    /// For Garbler -> completed adaptor signatures are ready.
    /// For Evaluator -> garbling table evaluation complete
    ///
    /// CANNOT USE THIS SETUP AGAIN TO PROCESS DEPOSITS.
    Consumed {
        /// Deposit which consumed this setup.
        deposit: RpcDepositId,
        /// Garbler -> always true
        /// Evaluator -> true -> final secret was extracted and can be used to sign transaction.
        ///           -> false -> final secret could not be extracted
        success: bool,
    },

    /// Setup was aborted due to some protocol violation.
    /// NEW SETUP IS REQUIRED.
    Aborted {
        /// Reason for aborting.
        /// This is mainly for debugging.
        reason: String,
    },
}
