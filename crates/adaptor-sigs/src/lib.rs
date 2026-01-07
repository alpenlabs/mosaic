//! Mosaic adaptor signatures library.

pub mod adaptor;
pub mod error;
pub(crate) mod fixed_base;

/// Number of coefficients in each polynomial.
pub const N_COEFFICIENTS: usize = 174;
/// Number of circuits (evaluation points).
pub const N_SHARES: usize = 181;
/// Number of input wires to the circuit.
pub const N_INPUT_WIRES: usize = 1273;
