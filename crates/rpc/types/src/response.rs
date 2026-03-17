//! Server response structures.

use std::error::Error;

use jsonrpsee_types::ErrorObject;

use crate::RpcDepositId;

/// Common error result type.
pub type RpcResult<T> = Result<T, RpcError>;

/// RPC error codes.
#[derive(Debug, thiserror::Error)]
pub enum RpcError {
    /// Caller passed an invalid argument.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// Operation not ready.
    #[error("not ready")]
    NotReady,

    /// Invalid statemachine id.
    #[error("invalid statemachine id")]
    InvalidStateMachineId,

    /// Missing statemachine.
    #[error("statemachine not found")]
    StateMachineNotFound,

    /// Cannot accept request at this statemachine state
    #[error("invalid input for state: {0}")]
    InvalidInputForState(String),

    /// Cannot create duplicate deposit.
    #[error("deposit id already exists: {0}")]
    DuplicateDeposit(RpcDepositId),

    /// Missing deposit.
    #[error("deposit not found")]
    DepositNotFound,

    /// Missing completed adaptor signatures.
    #[error("completed adaptor signatures not found")]
    CompletedSigsNotFound,

    /// Invalid adaptor sigs, could not parse to valid Signature
    #[error("adaptor cannot be parsed")]
    UnparsableAdaptorSigs,

    /// Storage error.
    #[error("storage: {0}")]
    Storage(Box<dyn Error>),

    /// Errot communicating with state machine executoe.
    #[error("executor: {0}")]
    SMExecutor(Box<dyn Error>),

    /// Not yet implemented.
    #[error("not yet implemented")]
    Unimplemented,

    /// Other.  For dev purposes.
    #[error("{0}")]
    Other(String),
}

impl RpcError {
    /// Create storage error variant.
    pub fn storage(err: impl Error + 'static) -> Self {
        Self::Storage(Box::new(err))
    }

    /// Create sm executor error variant.
    pub fn sm_executor(err: impl Error + 'static) -> Self {
        Self::SMExecutor(Box::new(err))
    }
}

impl RpcError {
    /// Gets the JSON-RPC error code to generate.
    pub fn code(&self) -> i32 {
        use RpcError::*;
        match self {
            InvalidArgument(_) => 1,
            NotReady => 2,
            InvalidStateMachineId => 10,
            StateMachineNotFound => 11,
            InvalidInputForState(_) => 12,
            DuplicateDeposit(_) => 20,
            DepositNotFound => 201,
            CompletedSigsNotFound => 202,
            UnparsableAdaptorSigs => 203,
            Storage(_) => 80,
            SMExecutor(_) => 81,
            Unimplemented => -99,
            Other(_) => -1,
        }
    }
}

impl From<RpcError> for ErrorObject<'static> {
    fn from(val: RpcError) -> Self {
        ErrorObject::owned(val.code(), format!("{}", val), Option::<i32>::None)
    }
}
