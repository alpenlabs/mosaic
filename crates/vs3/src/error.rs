//! Error types for the VS3 protocol.
use thiserror::Error;

use crate::polynomial::Index;

/// Error types for the VS3 protocol.
#[derive(Debug, Error)]
pub enum Error {
    /// A share commitment verification failed.
    #[error("share commitment mismatch at index {index}")]
    ShareCommitmentMismatch {
        /// The index of the share that failed the commitment verification.
        index: Index,
    },
    /// Batch share commitment verification failed (at least one share is invalid).
    #[error("batch share commitment verification failed")]
    BatchShareCommitmentMismatch,
    /// Invalid number of shares provided for interpolation.
    #[error("invalid share count: expected {expected}, got {actual}")]
    InvalidShareCount {
        /// The expected number of shares.
        expected: usize,
        /// The actual number of shares.
        actual: usize,
    },
    /// Missing reserved index (0) in known shares.
    #[error("missing reserved index in known shares")]
    MissingReservedIndex,
}
