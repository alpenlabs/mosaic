//! CaC protocol type definitions.
//!
//! This is for internally-focused types that we don't expect the bridge client
//! to ever interact with directly, so this can have types that we don't want to
//! expose in the RPC interface (or be compiled into RPC libraries).

mod adaptor;
mod msgs;
mod protocol;
pub mod state_machine;

pub use adaptor::*;
use mosaic_common::Byte32;
pub use msgs::*;
pub use protocol::*;

/// Commitment to a Garbling Table
pub type GarblingTableCommitment = Byte32;

/// Seed for deterministic Garbling Table generation
pub type Seed = Byte32;

/// Unique deposit id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DepositId(pub Byte32);

impl std::fmt::Display for DepositId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}
