//! Generic framework for resumable computation.
//!
//! This is designed around the kinds of computations that are heavily
//! parallelizable but still have a "loop" to them where we can pause and and
//! take a snapshot of the computation.  We assume that all of the "operational"
//! data can be kept in memory, although we are assumed to be doing IO with it.
//!
//! The operational data is the key part that we take snapshots of and export so
//! that we can resume from a saved point.  We assume that inputs are immutable
//! (ie. won't change over the course of computation) and that outputs are safe
//! to overwrite if we accidentally re-execute a step.

mod traits;
mod types;

pub use traits::*;
pub use types::*;
