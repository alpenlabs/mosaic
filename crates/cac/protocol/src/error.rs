use std::error::Error;

use mosaic_cac_types::DepositId;

/// State machine error
#[derive(Debug, thiserror::Error)]
pub enum SMError {
    /// Received Input that is not expected at current state.
    #[error("Received Input that is not expected at current state")]
    UnexpectedInput,
    /// Received Input whose data is invalid.
    #[error("Received Input whose data is invalid")]
    InvalidInputData,

    /// Received init for existing deposit.
    #[error("Received init for existing deposit: {0}")]
    DepositAlreadyExists(DepositId),
    /// Received input for unknown deposit id.
    #[error("Received input for unknown deposit id: {0}")]
    UnknownDeposit(DepositId),
    /// CRITICAL: State is inconsitent with expectations.
    #[error("CRITICAL: State is inconsitent with expectations: {0}")]
    StateInconsistency(&'static str),
    /// Error while accessing storage.
    #[error("Error while accessing storage: {0}")]
    Storage(Box<dyn Error>),
}

/// State machine result
pub type SMResult<T> = Result<T, SMError>;
