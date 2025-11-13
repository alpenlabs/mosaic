use serde::{Deserialize, Serialize};

/// Configuration provided as part of setting up a game instance.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RpcTablesetConfig {
    /// The name of the circuit we'll use.
    ///
    /// This matches the client configuration for where to find this circuit information.
    circuit_name: String,

    /// The role we're playing in the setup.
    role: RpcGarbRole,

    /// CaC game configuration.
    cac_config: RpcCacConfig,
}

/// The role the client should play in the garbling game.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RpcGarbRole {
    /// Garbler.
    Garbler,

    /// Evaluator.
    Evaluator,
}

/// Configuration for the CaC game.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RpcCacConfig {
    /// The number of tables we'll generate to start off.
    tables: u32,

    /// The number of tables to open as part of the setup process.
    open: u32,
}
