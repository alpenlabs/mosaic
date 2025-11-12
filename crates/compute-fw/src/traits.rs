use std::any::Any;

use bytes::Bytes;
use strata_codec::Codec;

use crate::types::{Snapshot, StepResult};

/// Describes a resumable computation.
pub trait Computation: Codec + Sync + Send + Sized + 'static {
    /// Input to the computation.
    type Input: Clone + Any + Codec;

    /// Serializable representation of the intermediate state.
    type SnapshotState: Clone + Codec;

    /// Starts the service using input and shared resources.
    fn start(inp: Self::Input) -> anyhow::Result<Self>;

    /// Resumes from a snapshot.
    fn resume(step: Self::SnapshotState) -> anyhow::Result<Self>;

    /// Exports the current state
    fn export(&self) -> Self::SnapshotState;

    /// Executes a step of the computation.
    ///
    /// This returning an `Err` indicates the step execution failed, but might
    /// be able to be retried.
    fn execute_step(&mut self) -> anyhow::Result<StepResult>;

    /// Gets a loggable name for the computation.
    fn name(&self) -> &str;
}

pub trait ComputeSnapshotProvider: Sync + Send + 'static {
    /// Loads a saved snapshot, if present.
    fn load_snapshot(&self) -> anyhow::Result<Option<Snapshot>>;

    /// Saves the snapshot state.
    fn save_snapshot(&self, ss: Snapshot) -> anyhow::Result<()>;

    /// Saves failure data for troubleshooting later.
    fn save_failure_data(self, fd: Bytes) -> anyhow::Result<()>;
}
