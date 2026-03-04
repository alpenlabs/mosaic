use std::error::Error;

use mosaic_cac_types::DepositId;

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
    #[error("Error while accessing storage: {0}")]
    Storage(Box<dyn Error>),
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
    pub fn storage(err: impl Error + 'static) -> Self {
        Self::Storage(Box::new(err))
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
        E: std::error::Error + 'static;
}

impl<T, E> ResultOptionExt<T, E> for Result<Option<T>, E> {
    fn require(self, message: &str) -> Result<T, SMError>
    where
        E: std::error::Error + 'static,
    {
        self.map_err(SMError::storage)?
            .ok_or_else(|| SMError::state_inconsistency(message))
    }
}
