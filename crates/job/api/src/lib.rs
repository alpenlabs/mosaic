//! API types for the Mosaic job scheduler.
//!
//! This crate defines the interface between the SM Scheduler and the Job
//! Scheduler. It is intentionally thin — only submission, result, and handle
//! types live here so that consumers (SM Scheduler) don't depend on the
//! scheduler implementation.
//!
//! The [`JobExecutor`] trait decouples the scheduler from executor
//! implementations: the scheduler routes actions and manages pools, while a
//! separate crate provides the concrete execution logic.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────┐     job-api types      ┌────────────────┐
//! │ SM Scheduler │ ◄────────────────────► │ Job Scheduler  │
//! └──────────────┘  submit / completion   └────────────────┘
//!                                                │
//!                                           JobExecutor
//!                                                │
//!                                         ┌────────────────┐
//!                                         │  Job Executors  │
//!                                         └────────────────┘
//! ```

mod handle;
mod submission;

use mosaic_cac_types::state_machine::{
    evaluator::Action as EvaluatorAction, garbler::Action as GarblerAction,
};
use mosaic_net_svc_api::PeerId;

pub use handle::{JobSchedulerHandle, SchedulerStopped};
pub use submission::{ActionCompletion, JobActions, JobBatch, JobCompletion};

/// Outcome of executing a job action.
///
/// The SM never sees failures. [`Done`](Self::Done) delivers the completion;
/// [`Retry`](Self::Retry) requeues the job so other peers can make progress
/// while this job waits for a transient condition to resolve.
#[derive(Debug)]
pub enum HandlerOutcome {
    /// Action completed successfully — deliver [`ActionCompletion`] to the SM.
    Done(ActionCompletion),
    /// Transient failure — requeue job to back of queue.
    Retry,
}

/// Executes actions on behalf of the job scheduler.
///
/// The scheduler calls these methods for each action it dequeues. The
/// implementation lives in a separate crate (`job-executors`) so the scheduler
/// has no compile-time dependency on execution logic (garbling, adaptors, etc.).
pub trait JobExecutor: Send + Sync + 'static {
    /// Execute a garbler action.
    fn execute_garbler(
        &self,
        peer_id: &PeerId,
        action: &GarblerAction,
    ) -> impl Future<Output = HandlerOutcome> + Send;

    /// Execute an evaluator action.
    fn execute_evaluator(
        &self,
        peer_id: &PeerId,
        action: &EvaluatorAction,
    ) -> impl Future<Output = HandlerOutcome> + Send;
}
