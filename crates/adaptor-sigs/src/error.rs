//! Error types for the cut-and-choose cryptographic library.

use thiserror::Error;

/// Library-wide error type.
///
/// Security boundary: Callers must ensure points/scalars are valid field/group elements. Otherwise,
/// all inputs may be malicious and must be validated here.
#[derive(Debug, Error)]
#[allow(missing_docs)]
pub enum Error {
    /// Verification failed (semantic mismatch without another more specific error).
    #[error("verification failed: {what}")]
    VerificationFailed { what: &'static str },

    /// Deserialization error.
    #[error("deserialization error: {0}")]
    Deserialization(&'static str),

    /// Deserialization error.
    #[error("deserialization error while checking point on curve")]
    DeserializationErrorInPointOnCurve,
}
