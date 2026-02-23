//! Shared state machine specific types.

pub mod evaluator;
pub mod garbler;
mod info;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
pub use info::StateMachineInfo;
use mosaic_common::Byte32;

/// Deterministic id for a state machine
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, CanonicalSerialize, CanonicalDeserialize)]
pub struct StateMachineId(Byte32);

impl From<[u8; 32]> for StateMachineId {
    fn from(value: [u8; 32]) -> Self {
        Self(value.into())
    }
}
