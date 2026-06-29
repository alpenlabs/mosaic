use std::{
    io::{self, Read},
    path::Path,
};

use ckt_fmtv5_types::v5::c::{HEADER_SIZE, HeaderV5c};
use serde::{Deserialize, Serialize};

use crate::RpcByte32;

/// Entry in the response for a configured circuit.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RpcCircuitInfoEntry {
    /// human readable identifier
    pub name: String,
    /// commitment to check circuit integrity
    pub commitment: RpcByte32,
    /// vk hash the circuit was generated for, taken from the v5c header memo
    /// field (all-zero for circuits generated without a vk, e.g. the test
    /// circuit).
    pub vk_hash: RpcByte32,
    /// additional metadata about the circuit
    pub info: RpcCircuitInfo,
}

impl RpcCircuitInfoEntry {
    /// Create circuit info by reading the v5c header from the circuit file at `path`.
    pub fn from_circuit_file(path: &Path) -> io::Result<Self> {
        let mut f = std::fs::File::open(path)?;
        let mut header_bytes = [0u8; HEADER_SIZE];
        f.read_exact(&mut header_bytes)?;
        let header = HeaderV5c::from_bytes(&header_bytes)?;

        let file_size = std::fs::metadata(path)?.len();

        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();

        Ok(Self {
            name,
            commitment: header.checksum.into(),
            vk_hash: header.memo.into(),
            info: RpcCircuitInfo {
                total_size_bytes: file_size,
                total_gates: header.total_gates(),
                xor_gates: header.xor_gates,
                and_gates: header.and_gates,
                num_input_wires: header.primary_inputs,
                num_output_wires: header.num_outputs,
            },
        })
    }
}

/// Info about a circuit that's been configured.
///
/// Consumers can use this to sanity check that the table we have is the same as
/// the table they're expecting and also maybe get an idea of how long it's
/// going to take to work with it.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RpcCircuitInfo {
    /// total circuit file size in bytes
    pub total_size_bytes: u64,
    /// total number of gates (xor + and)
    pub total_gates: u64,
    /// number of XOR gates
    pub xor_gates: u64,
    /// number of AND gates
    pub and_gates: u64,
    /// number of primary input wires
    pub num_input_wires: u64,
    /// number of output wires
    pub num_output_wires: u64,
}
