//! Cloneable handle for submitting jobs to the scheduler.
//!
//! The [`JobSchedulerHandle`] is the primary interface used by the SM Scheduler
//! to submit action batches and receive completed results. It communicates with
//! the [`JobScheduler`] via async channels and can be cloned freely across
//! tasks.

use kanal::{AsyncReceiver, AsyncSender};

use crate::{JobBatch, JobCompletion};

/// Handle for interacting with the job scheduler.
///
/// This is the API surface that the SM Scheduler uses. It is cheaply cloneable
/// and can be shared across tasks and threads.
///
/// # Example
///
/// ```ignore
/// use mosaic_cac_types::state_machine::garbler::ActionContainer;
///
/// // Submit a batch of actions produced by one STF call
/// handle.submit(JobBatch {
///     peer_id,
///     actions: JobActions::Garbler(garbler_action_container),
/// }).await?;
///
/// // Receive individual completed results
/// let completion = handle.recv().await?;
/// // Route completion.result back to the SM for completion.peer_id
/// ```
#[derive(Debug, Clone)]
pub struct JobSchedulerHandle {
    submit_tx: AsyncSender<JobBatch>,
    completion_rx: AsyncReceiver<JobCompletion>,
}

/// Error returned when the job scheduler has shut down.
#[derive(Debug)]
pub struct SchedulerStopped;

impl std::fmt::Display for SchedulerStopped {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("job scheduler is shut down")
    }
}

impl std::error::Error for SchedulerStopped {}

impl JobSchedulerHandle {
    /// Create a new handle from the submission and completion channels.
    ///
    /// This is called by the `JobScheduler` during construction. External
    /// consumers should obtain a handle from the scheduler, not construct
    /// one directly.
    #[doc(hidden)]
    pub fn new(
        submit_tx: AsyncSender<JobBatch>,
        completion_rx: AsyncReceiver<JobCompletion>,
    ) -> Self {
        Self {
            submit_tx,
            completion_rx,
        }
    }

    /// Submit a batch of actions for execution.
    ///
    /// One batch corresponds to the actions emitted by a single STF call.
    /// Each action is individually routed to the appropriate pool and produces
    /// its own [`JobCompletion`] via [`recv`](Self::recv).
    pub async fn submit(&self, batch: JobBatch) -> Result<(), SchedulerStopped> {
        self.submit_tx
            .send(batch)
            .await
            .map_err(|_| SchedulerStopped)
    }

    /// Receive the next completed job result.
    ///
    /// Blocks until a result is available or the scheduler shuts down.
    pub async fn recv(&self) -> Result<JobCompletion, SchedulerStopped> {
        self.completion_rx
            .recv()
            .await
            .map_err(|_| SchedulerStopped)
    }

    /// Try to receive a completed job result without blocking.
    ///
    /// Returns `None` if no results are available yet.
    pub fn try_recv(&self) -> Result<Option<JobCompletion>, SchedulerStopped> {
        match self.completion_rx.try_recv() {
            Ok(Some(completion)) => Ok(Some(completion)),
            Ok(None) => Ok(None),
            Err(_) => Err(SchedulerStopped),
        }
    }
}
