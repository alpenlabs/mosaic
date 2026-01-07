//! CaC protocol type definitions.
//!
//! This is for internally-focused types that we don't expect the bridge client
//! to ever interact with directly, so this can have types that we don't want to
//! expose in the RPC interface (or be compiled into RPC libraries).

mod adaptor;
mod msgs;

pub use adaptor::*;
use mosaic_common::Byte32;
pub use msgs::*;

/// Commitment to a Garbling Table
pub type GarblingTableCommitment = Byte32;

/// Seed for deterministic Garbling Table generation
pub type Seed = Byte32;
