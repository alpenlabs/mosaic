use std::error::Error;

use mosaic_cac_types::{DepositId, RetryableStorageError};

/// State machine error
#[derive(Debug, thiserror::Error)]
pub enum SMError {
    /// Root State not available.
    #[error("CRITICAL: Missing root state")]
    MissingRootState,
    /// Received Input that is not expected at current state.
    #[error("Received Input not expected at current state")]
    UnexpectedInput,
    /// Received Input whose data is invalid.
    #[error("Received Input with invalid data")]
    InvalidInputData,
    /// Received init for existing deposit.
    #[error("Received init for existing deposit: {0}")]
    DepositAlreadyExists(DepositId),
    /// Received input for unknown deposit id.
    #[error("Received input for unknown deposit id: {0}")]
    UnknownDeposit(DepositId),
    /// Received duplicate action.
    #[error("Received duplicate action")]
    DuplicateAction,
    /// CRITICAL: State is inconsistent with expectations.
    #[error("CRITICAL: State is inconsistent with expectations: {0}")]
    StateInconsistency(String),
    /// Error while accessing storage.
    #[error("Error while accessing storage: {source}")]
    Storage {
        /// Whether the underlying storage failure is safe to retry by
        /// discarding the current STF attempt and rerunning it from the start.
        retryable: bool,
        /// Original storage error.
        #[source]
        source: Box<dyn Error + Send + Sync>,
    },
}

impl SMError {
    /// Creates a missing root state error.
    pub fn missing_root_state() -> Self {
        Self::MissingRootState
    }

    /// Creates an unexpected input error.
    pub fn unexpected_input() -> Self {
        Self::UnexpectedInput
    }

    /// Creates an invalid input data error.
    pub fn invalid_input_data() -> Self {
        Self::InvalidInputData
    }

    /// Creates a deposit already exists error.
    pub fn deposit_already_exists(id: DepositId) -> Self {
        Self::DepositAlreadyExists(id)
    }

    /// Creates an unknown deposit error.
    pub fn unknown_deposit(id: DepositId) -> Self {
        Self::UnknownDeposit(id)
    }

    /// Creates a duplicate action error.
    pub fn duplicate_action() -> Self {
        Self::DuplicateAction
    }

    /// Creates a state inconsistency error.
    pub fn state_inconsistency(s: impl Into<String>) -> Self {
        Self::StateInconsistency(s.into())
    }

    /// Creates a storage error.
    pub fn storage(err: impl Error + RetryableStorageError + Send + Sync + 'static) -> Self {
        Self::Storage {
            retryable: err.is_retryable(),
            source: Box::new(err),
        }
    }

    /// Returns true when this error came from storage and the caller may
    /// safely retry the whole STF unit from the start.
    pub fn is_retryable_storage(&self) -> bool {
        match self {
            Self::Storage { retryable, .. } => *retryable,
            _ => false,
        }
    }
}

/// State machine result
pub type SMResult<T> = Result<T, SMError>;

/// Extension trait for `Result<Option<T>, E>` to simplify common error handling patterns.
pub trait ResultOptionExt<T, E> {
    /// Converts `Result<Option<T>, E>` to `Result<T, SMError>`.
    ///
    /// This combines `map_err` for storage errors and `ok_or_else` for missing state
    /// into a single method call.
    fn require(self, message: &str) -> Result<T, SMError>
    where
        E: std::error::Error + RetryableStorageError + Send + Sync + 'static;
}

impl<T, E> ResultOptionExt<T, E> for Result<Option<T>, E> {
    fn require(self, message: &str) -> Result<T, SMError>
    where
        E: std::error::Error + RetryableStorageError + Send + Sync + 'static,
    {
        self.map_err(SMError::storage)?
            .ok_or_else(|| SMError::state_inconsistency(message))
    }
}
