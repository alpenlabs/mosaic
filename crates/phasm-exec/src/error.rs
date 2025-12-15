//! Error types for the phasm executor.

use thiserror::Error;

/// Errors that can occur during phasm state machine execution.
#[derive(Debug, Error)]
pub enum Error {
    /// Failed to load state from persistence.
    #[error("failed to load state: {0}")]
    StateLoad(String),

    /// Failed to save state to persistence.
    #[error("failed to save state: {0}")]
    StateSave(String),

    /// Failed to load inputs from the durable queue.
    #[error("failed to load inputs: {0}")]
    InputLoad(String),

    /// Failed to persist an input to the durable queue.
    #[error("failed to persist input: {0}")]
    InputPersist(String),

    /// The state transition function returned an error.
    #[error("state transition failed: {0}")]
    TransitionFailed(String),

    /// The restore function returned an error.
    #[error("restore failed: {0}")]
    RestoreFailed(String),

    /// Tracked action execution failed after all retries.
    #[error("action execution failed after {attempts} attempts: {message}")]
    ActionFailed {
        /// Number of attempts made.
        attempts: u32,
        /// Description of the failure.
        message: String,
    },

    /// Worker was signaled to shut down.
    #[error("shutdown requested")]
    ShutdownRequested,

    /// Notification channel closed unexpectedly.
    #[error("notification channel closed")]
    ChannelClosed,
}

/// Result type alias for phasm executor operations.
pub type Result<T> = std::result::Result<T, Error>;
