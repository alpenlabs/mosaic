//! CaC protocol type definitions.
//!
//! This is for internally-focused types that we don't expect the bridge client
//! to ever interact with directly, so this can have types that we don't want to
//! expose in the RPC interface (or be compiled into RPC libraries).

// Used by examples
use ark_ec as _;
use ark_ff as _;
pub use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
// Used by benchmarks
#[cfg(test)]
use criterion as _;

mod adaptor;
mod msgs;
mod protocol;
pub mod state_machine;

pub use adaptor::*;
use mosaic_common::Byte32;
use mosaic_vs3::{Point, Scalar};
pub use msgs::*;
pub use protocol::*;

/// Commitment to a Garbling Table
pub type GarblingTableCommitment = Byte32;

/// Seed for deterministic Garbling Table generation
pub type Seed = Byte32;

/// Unique deposit id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, CanonicalSerialize, CanonicalDeserialize)]
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

/// A public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct SecretKey(pub Scalar);

/// A secret Key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PubKey(pub Point);

#[cfg(test)]
mod serde_tests;
