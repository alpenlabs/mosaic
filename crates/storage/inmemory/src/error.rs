//! Error types for in-memory storage operations.

use mosaic_cac_types::DepositId;
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
}
