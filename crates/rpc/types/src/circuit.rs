use serde::{Deserialize, Serialize};

use crate::RpcByte32;

/// Entry in the response for a configured circuit.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RpcCircuitInfoEntry {
    /// human readable identifier
    pub name: String,
    /// commitment to check circuit integrity
    pub commitment: RpcByte32,
    /// additional metadata about the circuit
    pub info: RpcCircuitInfo,
}

impl RpcCircuitInfoEntry {
    /// Create circuit info from config.
    pub fn from_config(/* TODO: mosaic config */) -> Self {
        Self {
            name: "default".into(),
            commitment: [0; 32].into(),
            info: RpcCircuitInfo {
                total_size_bytes: 0,
                total_gates: 0,
                levels: 0,
                max_width: 0,
                num_input_wires: 0,
                num_output_wires: 0,
            },
        }
    }
}

/// Info about a circuit that's been configured.
///
/// Consumers can use this to sanity check that the table we have is the same as
/// the table they're expecting and also maybe get an idea of how long it's
/// going to take to work with it.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RpcCircuitInfo {
    total_size_bytes: u64,
    total_gates: u64,
    levels: u64,
    max_width: u64,
    num_input_wires: u64,
    num_output_wires: u64,
}
