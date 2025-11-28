//! Database error types.

use thiserror::Error;

/// Errors that can occur during database operations.
#[derive(Debug, Error)]
pub enum DbError {
    /// The requested record was not found.
    #[error("record not found: {0}")]
    NotFound(String),

    /// A database constraint was violated.
    #[error("constraint violation: {0}")]
    ConstraintViolation(String),

    /// Serialization or deserialization failed.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// A transaction error occurred.
    #[error("transaction error: {0}")]
    Transaction(String),

    /// A connection error occurred.
    #[error("connection error: {0}")]
    Connection(String),

    /// An internal database error occurred.
    #[error("internal error: {0}")]
    Internal(String),
}

/// Result type for database operations.
pub type DbResult<T> = Result<T, DbError>;
