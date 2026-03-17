//! Service layer errors.

use std::error::Error;

use mosaic_cac_types::{DepositId, state_machine::StateMachineId};

/// Errors originating from the service layer.
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    /// State machine not found.
    #[error("statemachine not found: {0}")]
    StateMachineNotFound(StateMachineId),

    /// Invalid input for the current state machine step.
    #[error("invalid input for state: {0}")]
    InvalidInputForState(String),

    /// Deposit already exists.
    #[error("duplicate deposit: {0}")]
    DuplicateDeposit(DepositId),

    /// Deposit not found.
    #[error("deposit not found")]
    DepositNotFound,

    /// Completed adaptor signatures not found when expected.
    #[error("completed adaptor sigs not found")]
    CompletedSigsNotFound,

    /// Invalid adaptor signatures — could not parse.
    #[error("unparsable adaptor signatures")]
    UnparsableAdaptorSigs,

    /// Invalid argument passed by caller.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// Role mismatch — operation not valid for the state machine's role.
    #[error("role mismatch: {0}")]
    RoleMismatch(String),

    /// Unexpected internal state.
    #[error("unexpected state: {0}")]
    UnexpectedState(String),

    /// Storage backend error.
    #[error("storage: {0}")]
    Storage(Box<dyn Error + Send>),

    /// State machine executor communication error.
    #[error("executor: {0}")]
    Executor(Box<dyn Error + Send>),
}

/// Service result type.
pub type ServiceResult<T> = Result<T, ServiceError>;

impl ServiceError {
    /// Create storage error variant.
    pub fn storage(err: impl Error + Send + 'static) -> Self {
        Self::Storage(Box::new(err))
    }

    /// Create executor error variant.
    pub fn executor(err: impl Error + Send + 'static) -> Self {
        Self::Executor(Box::new(err))
    }
}
