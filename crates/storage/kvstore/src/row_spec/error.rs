//! Error types for row/key/value encoding and keyspace decoding.

use ark_serialize::SerializationError;
use thiserror::Error;

#[derive(Debug, Error)]
/// Errors while decoding row-local key bytes.
pub enum ArkKeyUnpackError {
    /// Failed to deserialize a key component.
    #[error("failed to deserialize key component: {0}")]
    Deserialize(SerializationError),
    /// Key bytes length did not match expected fixed width.
    #[error("invalid key length: expected {expected}, got {found}")]
    InvalidLength {
        /// Expected key size in bytes.
        expected: usize,
        /// Found key size in bytes.
        found: usize,
    },
    /// The byte buffer had extra data after decoding.
    #[error("unexpected trailing bytes in key")]
    TrailingBytes,
}

#[derive(Debug, Error)]
#[error("serialization: {0}")]
/// Wrapper for arkworks serialization failures.
pub struct ArkSerializationError(SerializationError);

impl From<SerializationError> for ArkSerializationError {
    fn from(error: SerializationError) -> Self {
        Self(error)
    }
}

#[derive(Debug, Error)]
/// Errors while validating and decoding a full keyspace envelope.
pub enum KeyspaceDecodeError<E: std::error::Error + Send + Sync + 'static> {
    /// Key was shorter than required or missing expected prefix bytes.
    #[error("key does not start with expected prefix")]
    MissingPrefix,
    /// Schema version byte did not match.
    #[error("bad key version: expected {expected}, got {found}")]
    BadVersion {
        /// Expected schema version.
        expected: u8,
        /// Actual schema version.
        found: u8,
    },
    /// Domain byte did not match the row specification.
    #[error("bad key domain: expected {expected}, got {found}")]
    BadDomain {
        /// Expected domain discriminator.
        expected: u8,
        /// Actual domain discriminator.
        found: u8,
    },
    /// Row tag byte did not match the row specification.
    #[error("bad row tag: expected {expected}, got {found}")]
    BadRowTag {
        /// Expected row tag.
        expected: u8,
        /// Actual row tag.
        found: u8,
    },
    /// Row-local key decoding failed.
    #[error("failed to unpack row-local key: {0}")]
    KeyUnpack(E),
}
