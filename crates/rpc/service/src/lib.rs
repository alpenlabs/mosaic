//! Transport-agnostic service layer for Mosaic.
//!
//! Provides the [`MosaicApi`] trait — the main programmatic interface for
//! controlling Mosaic, used by the bridge and any other consumer.
//! The RPC server is one frontend for this API, but it can be replaced.

mod default;
mod error;
mod schnorr_signer;
mod traits;
mod types;

pub use default::*;
pub use error::*;
pub use traits::*;
pub use types::*;

#[cfg(test)]
mod tests;
