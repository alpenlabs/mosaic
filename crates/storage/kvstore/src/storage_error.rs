//! Shared errors for KV-backed storage adapters.
use std::error::Error;

use mosaic_cac_types::{DepositId, RetryableStorageError};
use thiserror::Error;

#[derive(Debug, Error)]
/// Shared errors for KV-backed storage adapters.
pub enum StorageError {
    /// Failed to pack a typed key into raw bytes.
    #[error("keypack: {0}")]
    KeyPack(Box<dyn Error + Send + Sync>),
    /// Failed to unpack a raw key into a typed key.
    #[error("keyunpack: {0}")]
    KeyUnpack(Box<dyn Error + Send + Sync>),
    /// Failed to serialize a typed value into bytes.
    #[error("valueserialize: {0}")]
    ValueSerialize(Box<dyn Error + Send + Sync>),
    /// Failed to deserialize bytes into a typed value.
    #[error("valuedeserialize: {0}")]
    ValueDeserialize(Box<dyn Error + Send + Sync>),
    /// Underlying KV backend error.
    #[error("kvstore: {source}")]
    KvStore {
        /// Whether retrying the whole logical operation is safe.
        retryable: bool,
        /// Original backend error.
        #[source]
        source: Box<dyn Error + Send + Sync>,
    },
    /// Received unexpected reserved index 0.
    #[error("Received unexpected Index(0)")]
    UnexpectedZeroIndex,
    /// Received input for unknown deposit id.
    #[error("Received input for unknown deposit id: {0}")]
    UnknownDeposit(DepositId),
    /// Critical state inconsistency with expected invariants.
    #[error("CRITICAL: State is inconsistent with expectations: {0}")]
    StateInconsistency(String),
    /// Invalid argument passed by the caller.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
}

impl StorageError {
    pub(crate) fn key_pack(err: impl Error + Send + Sync + 'static) -> Self {
        Self::KeyPack(Box::new(err))
    }

    pub(crate) fn key_unpack(err: impl Error + Send + Sync + 'static) -> Self {
        Self::KeyUnpack(Box::new(err))
    }

    pub(crate) fn value_serialize(err: impl Error + Send + Sync + 'static) -> Self {
        Self::ValueSerialize(Box::new(err))
    }

    pub(crate) fn value_deserialize(err: impl Error + Send + Sync + 'static) -> Self {
        Self::ValueDeserialize(Box::new(err))
    }

    pub(crate) fn kvstore(err: impl Error + RetryableStorageError + Send + Sync + 'static) -> Self {
        Self::KvStore {
            retryable: err.is_retryable(),
            source: Box::new(err),
        }
    }

    pub(crate) fn unknown_deposit(id: DepositId) -> Self {
        Self::UnknownDeposit(id)
    }

    pub(crate) fn state_inconsistency(s: impl Into<String>) -> Self {
        Self::StateInconsistency(s.into())
    }

    pub(crate) fn invalid_argument(s: impl Into<String>) -> Self {
        Self::InvalidArgument(s.into())
    }
}

impl RetryableStorageError for StorageError {
    fn is_retryable(&self) -> bool {
        match self {
            Self::KvStore { retryable, .. } => *retryable,
            Self::KeyPack(_)
            | Self::KeyUnpack(_)
            | Self::ValueSerialize(_)
            | Self::ValueDeserialize(_)
            | Self::UnexpectedZeroIndex
            | Self::UnknownDeposit(_)
            | Self::StateInconsistency(_)
            | Self::InvalidArgument(_) => false,
        }
    }
}
