use serde::{Deserialize, Serialize};

/// Info about a CaC game.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GameInfo {
    circuit_name: String,
    role: CacRole,
    config: CacConfig,
    state: GameState,
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

/// Configuration for the CaC game.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CacConfig {
    /// The number of tables we'll generate to start off.
    tables: u32,

    /// The number of tables to open as part of the setup process.
    open: u32,
}

/// Describes the high-level state of a game.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum GameState {
    /// In the setup process.
    Setup,

    /// Setup finished, ready to eval.
    Idle,

    /// Evaluating.
    Evaling,

    /// Evaluated.
    Evaled,

    /// Dishonesty detected, aborted.
    Abort,
}
