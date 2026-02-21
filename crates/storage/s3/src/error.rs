//! Error types for the S3-backed table store.

use thiserror::Error;

/// Errors from S3 table store operations.
#[derive(Debug, Error)]
pub enum S3Error {
    /// Error from the underlying `object_store` crate.
    #[error("object store: {0}")]
    ObjectStore(#[from] object_store::Error),

    /// The background tokio runtime shut down unexpectedly.
    #[error("S3 table store background runtime shut down")]
    RuntimeShutdown,

    /// Channel communication with the background runtime failed.
    #[error("channel error: {0}")]
    Channel(String),

    /// Metadata deserialization failed.
    #[error("invalid metadata: {0}")]
    InvalidMetadata(String),

    /// The requested table was not found.
    #[error("table not found: {path}")]
    NotFound {
        /// The object path that was not found.
        path: String,
    },

    /// An I/O error during streaming read/write.
    #[error("stream I/O: {0}")]
    StreamIo(String),
}
