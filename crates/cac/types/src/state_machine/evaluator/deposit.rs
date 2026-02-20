use mosaic_common::constants::N_ADAPTOR_MSG_CHUNKS;

use crate::{HeapArray, SecretKey};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepositState {
    pub step: DepositStep,
    pub sk: SecretKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DepositStep {
    GeneratingAdaptors {
        deposit: bool,
        withdrawal_chunks: HeapArray<bool, N_ADAPTOR_MSG_CHUNKS>,
    },
    /// Sending adaptor message chunks to the garbler.
    /// Transitions to `DepositReady` when all chunks are acked.
    SendingAdaptors {
        /// Track which adaptor message chunks have been acked.
        acked: HeapArray<bool, N_ADAPTOR_MSG_CHUNKS>,
    },
    DepositReady,
    WithdrawnUndisputed,
    Aborted {
        reason: String,
    },
}

impl Default for DepositStep {
    fn default() -> Self {
        DepositStep::GeneratingAdaptors {
            deposit: false,
            withdrawal_chunks: HeapArray::from_elem(false),
        }
    }
}
