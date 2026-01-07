use std::future::Future;

use serde::{Serialize, de::DeserializeOwned};
use tokio_util::sync::CancellationToken;

/// A resumable, long-running job.
///
/// The job is agnostic to persistence and identity - the manager handles that
/// by capturing context in the `on_snapshot` closure.
pub trait ResumableJob: Send + 'static {
    /// Input provided when starting the job.
    type Input: Send + Serialize + DeserializeOwned;

    /// Final output produced on completion.
    type Output: Send + Serialize + DeserializeOwned;

    /// Opaque state for resumption.
    type Snapshot: Send + Serialize + DeserializeOwned;

    /// Error type for job failures.
    type Error: Send;

    /// Unique job type identifier.
    const JOB_TYPE: &'static str;

    /// Execute the job.
    ///
    /// # Arguments
    /// * `input` - Job parameters
    /// * `snapshot` - State to resume from, or `None` for a fresh start
    /// * `on_snapshot` - Callback to emit snapshots for persistence
    /// * `cancel` - Token to signal graceful shutdown
    fn start(
        self,
        input: Self::Input,
        snapshot: Option<Self::Snapshot>,
        on_snapshot: Box<dyn Fn(Self::Snapshot) + Send + Sync>,
        cancel: CancellationToken,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send;
}
