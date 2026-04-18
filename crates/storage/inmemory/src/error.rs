//! Error types for in-memory storage operations.

use mosaic_cac_types::{DepositId, RetryableStorageError};
use thiserror::Error;

/// Errors that can occur during database operations.
#[derive(Debug, Error)]
pub enum DbError {
    /// Received unexpected reserved index 0.
    #[error("Received unexpected Index(0)")]
    UnexpectedZeroIndex,

    /// Received input for unknown deposit id.
    #[error("Received input for unknown deposit id: {0}")]
    UnknownDeposit(DepositId),

    /// CRITICAL: State is inconsistent with expectations.
    #[error("CRITICAL: State is inconsistent with expectations: {0}")]
    StateInconsistency(String),

    /// Invalid argument passed by the caller.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
}

impl DbError {
    /// Creates an unknown deposit error.
    pub fn unknown_deposit(id: DepositId) -> Self {
        Self::UnknownDeposit(id)
    }

    /// Creates a state inconsistency error.
    pub fn state_inconsistency(s: impl Into<String>) -> Self {
        Self::StateInconsistency(s.into())
    }

    /// Creates an invalid argument error.
    pub fn invalid_argument(s: impl Into<String>) -> Self {
        Self::InvalidArgument(s.into())
    }
}

impl RetryableStorageError for DbError {
    fn is_retryable(&self) -> bool {
        false
    }
}
