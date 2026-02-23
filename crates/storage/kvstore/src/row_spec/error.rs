use ark_serialize::SerializationError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ArkKeyUnpackError {
    #[error("failed to deserialize key component: {0}")]
    Deserialize(SerializationError),
    #[error("unexpected trailing bytes in key")]
    TrailingBytes,
}

#[derive(Debug, Error)]
#[error("serialization: {0}")]
pub struct ArkSerializationError(SerializationError);

impl From<SerializationError> for ArkSerializationError {
    fn from(error: SerializationError) -> Self {
        Self(error)
    }
}

#[derive(Debug, Error)]
pub enum KeyspaceDecodeError<E: std::error::Error + Send + Sync + 'static> {
    #[error("key does not start with expected prefix")]
    MissingPrefix,
    #[error("bad key version: expected {expected}, got {found}")]
    BadVersion { expected: u8, found: u8 },
    #[error("bad key domain: expected {expected}, got {found}")]
    BadDomain { expected: u8, found: u8 },
    #[error("bad row tag: expected {expected}, got {found}")]
    BadRowTag { expected: u8, found: u8 },
    #[error("failed to unpack row-local key: {0}")]
    KeyUnpack(E),
}
