//! CaC protocol type definitions.
//!
//! This is for internally-focused types that we don't expect the bridge client
//! to ever interact with directly, so this can have types that we don't want to
//! expose in the RPC interface (or be compiled into RPC libraries).

// Used by examples
pub use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
// Used by benchmarks
#[cfg(test)]
use criterion as _;

pub mod adaptor;
mod keypair;
mod msgs;
mod protocol;
mod seed;
pub mod state_machine;

pub use adaptor::{Adaptor, Signature};
pub use keypair::*;
use mosaic_common::Byte32;
pub use msgs::*;
pub use protocol::*;
pub use seed::Seed;
use serde::{Deserialize, Serialize};

/// Commitment to a Garbling Table
pub type GarblingTableCommitment = Byte32;

/// Unique deposit id.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    CanonicalSerialize,
    CanonicalDeserialize,
)]
pub struct DepositId(pub Byte32);

impl std::fmt::Display for DepositId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl<T: Into<Byte32>> From<T> for DepositId {
    fn from(value: T) -> Self {
        DepositId(value.into())
    }
}

/// Sighash used in transaction signing;
#[derive(Debug, Clone, Copy, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Sighash(pub Byte32);

impl<T: Into<Byte32>> From<T> for Sighash {
    fn from(value: T) -> Self {
        Sighash(value.into())
    }
}

#[cfg(test)]
mod serde_tests;
