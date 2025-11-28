//! Job manager error types.

use mosaic_db_types::DbError;
use thiserror::Error;

/// Errors that can occur during job management.
#[derive(Debug, Error)]
pub enum JobError {
    /// The job was not found.
    #[error("job not found: {0}")]
    NotFound(u64),

    /// The job is in an invalid state for the requested operation.
    #[error("invalid job state: expected {expected}, got {actual}")]
    InvalidState {
        /// The expected state.
        expected: String,
        /// The actual state.
        actual: String,
    },

    /// A database error occurred.
    #[error("database error: {0}")]
    Database(#[from] DbError),

    /// Job execution failed.
    #[error("job execution failed: {0}")]
    Execution(String),

    /// Snapshot serialization/deserialization failed.
    #[error("snapshot error: {0}")]
    Snapshot(String),

    /// The job was cancelled.
    #[error("job cancelled")]
    Cancelled,

    /// The job manager is shutting down.
    #[error("job manager shutting down")]
    ShuttingDown,
}

/// Result type for job manager operations.
pub type JobResult<T> = Result<T, JobError>;
