//! Error types for the VS3 protocol.
use thiserror::Error;

use crate::polynomial::Index;

/// Error types for the VS3 protocol.
#[derive(Debug, Error)]
#[allow(missing_docs)]
pub enum Error {
    /// A share commitment verification failed.
    #[error("share commitment mismatch at index {index}")]
    ShareCommitmentMismatch { index: Index },
    /// Invalid number of shares provided for interpolation.
    #[error("invalid share count: expected {expected}, got {actual}")]
    InvalidShareCount { expected: usize, actual: usize },
    /// Missing reserved index (0) in known shares.
    #[error("missing reserved index in known shares")]
    MissingReservedIndex,
}
