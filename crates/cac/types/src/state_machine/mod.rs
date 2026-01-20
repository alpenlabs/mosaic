//! Shared state machine specific types.

pub mod evaluator;
pub mod garbler;
mod info;

pub use info::StateMachineInfo;
use mosaic_common::Byte32;

/// Deterministic id for a state machine
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StateMachineId(Byte32);
