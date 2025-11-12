//! Server response structures.

use jsonrpsee_types::ErrorObject;
use thiserror::Error;

/// Common error result type.
pub type RpcResult<T> = Result<T, RpcError>;

/// RPC error codes.
#[derive(Debug, Error)]
pub enum RpcError {
    /// Caller passed an invalid argument.
    #[error("invalid argument")]
    InvalidArgument,

    /// Operation not ready.
    #[error("not ready")]
    NotReady,

    /// Not yet implemented.
    #[error("not yet implemented")]
    Unimplemented,

    /// Other.  For dev purposes.
    #[error("{0}")]
    Other(String),
}

impl RpcError {
    /// Gets the JSON-RPC error code to generate.
    pub fn code(&self) -> i32 {
        use RpcError::*;
        match self {
            InvalidArgument => 1,
            NotReady => 2,
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
