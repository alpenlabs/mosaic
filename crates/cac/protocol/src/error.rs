use std::error::Error;

use mosaic_cac_types::MsgId;

use crate::garbler::deposit::DepositId;

/// State machine error
#[derive(Debug)]
pub enum SMError {
    /// Received Input that is not expected at current state.
    UnexpectedInput,
    /// Received Input whose data is invalid.
    InvalidInputData,
    /// Received Ack for unexpected msg id.
    UnexpectedMsgId(MsgId),
    /// Received init for existing deposit.
    DepositAlreadyExists(DepositId),
    /// Received input for unknown deposit id.
    UnknownDeposit(DepositId),
    /// CRITICAL: State is inconsitent with expectations.
    StateInconsistency(&'static str),
    /// Error while accessing storage.
    Storage(Box<dyn Error>),
}

/// State machine result
pub type SMResult<T> = Result<T, SMError>;
