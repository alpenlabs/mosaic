//! Job trait definition.

use serde::{de::DeserializeOwned, Serialize};
use std::fmt::Debug;

use crate::error::JobError;

/// Result of executing a single job step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepResult {
    /// More steps remain to be executed.
    Continue,
    /// The job has completed successfully.
    Complete,
}

impl StepResult {
    /// Returns true if the job should continue executing.
    pub fn should_continue(&self) -> bool {
        matches!(self, Self::Continue)
    }

    /// Returns true if the job is complete.
    pub fn is_complete(&self) -> bool {
        matches!(self, Self::Complete)
    }
}

/// Context provided to jobs during execution.
///
/// This provides jobs with access to services they may need during execution,
/// such as progress reporting and cancellation checking.
#[derive(Debug)]
pub struct JobContext {
    /// Whether the job has been requested to cancel.
    cancelled: bool,
}

impl JobContext {
    /// Create a new job context.
    pub(crate) fn new() -> Self {
        Self { cancelled: false }
    }

    /// Check if the job has been cancelled.
    ///
    /// Jobs should check this periodically and return early if true.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled
    }

    /// Mark the job as cancelled.
    pub(crate) fn cancel(&mut self) {
        self.cancelled = true;
    }
}

/// Trait for job implementations.
///
/// Jobs are long-running operations that can be paused, resumed, and recovered
/// after crashes. They execute in discrete steps, with snapshots taken between
/// steps to enable crash recovery.
///
/// # Example
///
/// ```ignore
/// use mosaic_job_manager::{Job, JobContext, StepResult};
/// use serde::{Serialize, Deserialize};
///
/// #[derive(Serialize, Deserialize)]
/// struct TableGenConfig {
///     circuit_name: String,
///     num_tables: u32,
/// }
///
/// struct TableGenJob {
///     config: TableGenConfig,
///     current_table: u32,
/// }
///
/// impl Job for TableGenJob {
///     type Config = TableGenConfig;
///     type Output = Vec<u8>;  // Table data
///     type Error = std::io::Error;
///
///     fn job_type() -> &'static str {
///         "table_generation"
///     }
///
///     fn new(config: Self::Config) -> Result<Self, Self::Error> {
///         Ok(Self { config, current_table: 0 })
///     }
///
///     fn step(&mut self, ctx: &JobContext) -> Result<StepResult, Self::Error> {
///         if ctx.is_cancelled() {
///             return Ok(StepResult::Complete);
///         }
///
///         // Generate one table
///         self.current_table += 1;
///
///         if self.current_table >= self.config.num_tables {
///             Ok(StepResult::Complete)
///         } else {
///             Ok(StepResult::Continue)
///         }
///     }
///
///     fn snapshot(&self) -> Vec<u8> {
///         // Serialize current_table
///         self.current_table.to_le_bytes().to_vec()
///     }
///
///     fn restore(snapshot: &[u8], config: &Self::Config) -> Result<Self, Self::Error> {
///         let current_table = u32::from_le_bytes(snapshot.try_into().unwrap());
///         Ok(Self { config: config.clone(), current_table })
///     }
///
///     fn total_work_units(&self) -> Option<u64> {
///         Some(self.config.num_tables as u64)
///     }
///
///     fn completed_work_units(&self) -> u64 {
///         self.current_table as u64
///     }
/// }
/// ```
pub trait Job: Send + 'static {
    /// Configuration type for this job.
    type Config: Serialize + DeserializeOwned + Clone + Send + 'static;

    /// Output type produced when the job completes.
    type Output: Serialize + DeserializeOwned + Send + 'static;

    /// Error type for job failures.
    type Error: std::error::Error + Send + 'static;

    /// Returns the job type identifier.
    ///
    /// This is used to identify jobs in the database and for recovery.
    fn job_type() -> &'static str;

    /// Create a new job from configuration.
    fn new(config: Self::Config) -> Result<Self, Self::Error>
    where
        Self: Sized;

    /// Execute one step of the job.
    ///
    /// Returns `StepResult::Continue` if more steps remain, or
    /// `StepResult::Complete` when the job is done.
    ///
    /// Jobs should periodically check `ctx.is_cancelled()` and return
    /// early if the job has been cancelled.
    fn step(&mut self, ctx: &JobContext) -> Result<StepResult, Self::Error>;

    /// Serialize the current job state for snapshotting.
    ///
    /// This is called after each step to persist progress.
    fn snapshot(&self) -> Vec<u8>;

    /// Restore a job from a snapshot.
    ///
    /// Called during recovery to resume a job from its last checkpoint.
    fn restore(snapshot: &[u8], config: &Self::Config) -> Result<Self, Self::Error>
    where
        Self: Sized;

    /// Get the output of a completed job.
    ///
    /// This is only called after the job has completed successfully.
    fn output(&self) -> Result<Self::Output, Self::Error>;

    /// Total number of work units for this job, if known.
    ///
    /// Used for progress reporting. Return `None` if unknown.
    fn total_work_units(&self) -> Option<u64> {
        None
    }

    /// Number of work units completed so far.
    ///
    /// Used for progress reporting.
    fn completed_work_units(&self) -> u64 {
        0
    }
}

/// Type-erased job wrapper for runtime dispatch.
pub(crate) trait DynJob: Send {
    /// Execute one step.
    fn step(&mut self, ctx: &JobContext) -> Result<StepResult, JobError>;

    /// Create a snapshot.
    fn snapshot(&self) -> Vec<u8>;

    /// Get total work units.
    fn total_work_units(&self) -> Option<u64>;

    /// Get completed work units.
    fn completed_work_units(&self) -> u64;
}

impl<J: Job> DynJob for J {
    fn step(&mut self, ctx: &JobContext) -> Result<StepResult, JobError> {
        J::step(self, ctx).map_err(|e| JobError::Execution(e.to_string()))
    }

    fn snapshot(&self) -> Vec<u8> {
        J::snapshot(self)
    }

    fn total_work_units(&self) -> Option<u64> {
        J::total_work_units(self)
    }

    fn completed_work_units(&self) -> u64 {
        J::completed_work_units(self)
    }
}
