//! Evaluator state machine types for deposit operations.

use mosaic_common::constants::N_ADAPTOR_MSG_CHUNKS;
use serde::{Deserialize, Serialize};

use crate::{HeapArray, SecretKey};

/// State for an evaluator managing a deposit operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositState {
    /// Current step in the deposit state machine.
    pub step: DepositStep,
    /// Evaluator's adaptor secret key for this deposit.
    pub sk: SecretKey,
}

crate::state_machine::define_step_phase! {
    DepositStepPhase;
    /// Steps in the evaluator's deposit state machine.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub enum DepositStep {
        /// Generating adaptor signatures for deposit and withdrawal.
        GeneratingAdaptors {
            /// Whether the deposit adaptor has been generated.
            deposit: bool,
            /// Which withdrawal message chunks have been generated.
            withdrawal_chunks: HeapArray<bool, N_ADAPTOR_MSG_CHUNKS>,
        },
        /// Sending adaptor message chunks to the garbler.
        /// Transitions to `DepositReady` when all chunks are acked.
        SendingAdaptors {
            /// Track which adaptor message chunks have been acked.
            acked: HeapArray<bool, N_ADAPTOR_MSG_CHUNKS>,
        },
        /// Deposit is ready and waiting for completion.
        DepositReady,
        /// Funds have been withdrawn without dispute.
        WithdrawnUndisputed,
        /// Deposit operation was aborted.
        Aborted {
            /// Reason for the abort.
            reason: String,
        },
    }
}

impl Default for DepositStep {
    fn default() -> Self {
        DepositStep::GeneratingAdaptors {
            deposit: false,
            withdrawal_chunks: HeapArray::from_elem(false),
        }
    }
}
