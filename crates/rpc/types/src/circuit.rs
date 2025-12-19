use mosaic_cac_proto_types::Byte32;
use serde::{Deserialize, Serialize};

/// Entry in the response for a configured circuit.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RpcCircuitInfoEntry {
    // human readable identifier
    name: String,
    // commitment to check circuit integrity
    commitment: Byte32,
    // additional metadata about the circuit
    info: RpcCircuitInfo,
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
