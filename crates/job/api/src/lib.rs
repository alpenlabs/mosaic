//! API types for the Mosaic job scheduler.
//!
//! This crate defines the interface between the SM Scheduler and the Job
//! Scheduler. It is intentionally thin — only submission, result, and handle
//! types live here so that consumers (SM Scheduler) don't depend on the
//! scheduler implementation.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────┐     job-api types      ┌────────────────┐
//! │ SM Scheduler │ ◄────────────────────► │ Job Scheduler  │
//! └──────────────┘  submit / completion   └────────────────┘
//! ```

mod handle;
mod submission;

pub use handle::{JobSchedulerHandle, SchedulerStopped};
pub use submission::{ActionCompletion, JobActions, JobBatch, JobCompletion, JobError, JobResult};
