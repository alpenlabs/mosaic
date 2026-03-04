use mosaic_common::constants::N_ADAPTOR_MSG_CHUNKS;
use serde::{Deserialize, Serialize};

use crate::{HeapArray, PubKey};

/// State machine steps for processing a deposit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DepositStep {
    /// Waiting for adaptor signature message chunks.
    WaitingForAdaptors {
        /// Track which adaptor message chunks have been received.
        chunks: HeapArray<bool, N_ADAPTOR_MSG_CHUNKS>,
    },
    /// Verifying received adaptor signatures.
    VerifyingAdaptors,
    /// Deposit is ready for withdrawal.
    DepositReady,
    /// Deposit was withdrawn without dispute.
    WithdrawnUndisputed,
    /// Deposit processing was aborted.
    Aborted {
        /// Reason for aborting the deposit.
        reason: String,
    },
}

impl Default for DepositStep {
    fn default() -> Self {
        DepositStep::WaitingForAdaptors {
            chunks: HeapArray::from_elem(false),
        }
    }
}

/// State for tracking an individual deposit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositState {
    /// Current step in the deposit state machine.
    pub step: DepositStep,
    /// Pubkey for verifying adaptors for this deposit.
    pub pk: PubKey,
}
