//! Mosaic client RPC server impl.

// needed to suppress unused warning, I'm sure this will end up being needed at
// some future point
use jsonrpsee as _;

mod server;

pub use server::*;
