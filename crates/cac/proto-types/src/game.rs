use mosaic_common::{PeerId, constants::N_SETUP_INPUT_WIRES};
use serde::{Deserialize, Serialize};

use crate::TablesetInstanceId;

/// Info about a CaC game.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TablesetSetupInfo {
    circuit_name: String,
    role: CacRole,
    cac_params: CacParams,
    setup_inputs: SetupWireInputs,
    instance: TablesetInstanceId,
    peer: PeerId,
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
pub enum CacParams {
    /// default
    N181K174,
    /// for testing (only available in debug builds)
    #[cfg(debug_assertions)]
    N5K3,
}

impl CacParams {
    /// Total number of tables.
    pub fn tables(&self) -> u64 {
        match self {
            CacParams::N181K174 => 181,
            #[cfg(debug_assertions)]
            CacParams::N5K3 => 5,
        }
    }

    /// Number of openings during Cac.
    pub fn selected_openings(&self) -> u64 {
        match self {
            CacParams::N181K174 => 174,
            #[cfg(debug_assertions)]
            CacParams::N5K3 => 3,
        }
    }
}

/// Input wire values provided during setup.
/// This corresponds to operator bridge pubkey.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SetupWireInputs([u8; N_SETUP_INPUT_WIRES]);
