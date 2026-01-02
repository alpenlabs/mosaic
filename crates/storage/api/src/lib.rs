//! Storage interface for mosaic.

mod job;
mod state_machine;

pub use job::JobStateDb;
pub use state_machine::StateMachineDb;
use thiserror::Error;

/// Storage Error.
#[derive(Debug, Error)]
pub enum StorageError {
    // TODO: error types
    /// Failed to serialize/deserialize.
    #[error("Serialization: {0}")]
    Serialization(String),
    /// Other type of error not covered above.
    #[error("storage: {0}")]
    Other(String),
}

/// Storage Result
pub type StorageResult<T> = Result<T, StorageError>;
