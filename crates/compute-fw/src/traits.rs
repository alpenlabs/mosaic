use strata_codec::Codec;

use bytes::Bytes;

use crate::types::StepResult;

/// Describes a resumable computation.
pub trait Computation<'r>: Sized {
    /// Some generic resources that we require from the executor thread.
    ///
    /// This might be something like a threadpool handle.
    type Resources;

    /// Input to the computation.
    type Input: Clone + Codec;

    /// Serializable representation of the intermediate state.
    type SnapshotState: Clone + Codec;

    /// Starts the service using input and shared resources.
    fn start(inp: Self::Input, res: &'r Self::Resources) -> anyhow::Result<Self>;

    /// Resumes from a snapshot.
    fn resume(step: Self::SnapshotState, res: &'r Self::Resources) -> anyhow::Result<Self>;

    /// Exports the current state
    fn export(&self) -> Self::SnapshotState;

    /// Executes a step of the computation.
    ///
    /// This returning an `Err` indicates the step execution failed, but might
    /// be able to be retried.
    fn execute_step(&mut self) -> anyhow::Result<StepResult>;
}

pub trait ComputeSnapshotProvider {
    /// Loads a saved snapshot, if present.
    fn load_snapshot(&self) -> anyhow::Result<Bytes>;

    /// Saves the snapshot state.
    fn save_snapshot(&self, ss: Bytes) -> anyhow::Result<()>;
}
