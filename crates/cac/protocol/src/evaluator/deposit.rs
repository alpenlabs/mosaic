use mosaic_cac_types::{HeapArray, SecretKey};
use mosaic_common::constants::N_ADAPTOR_MSG_CHUNKS;

#[derive(Debug)]
#[expect(dead_code)]
pub struct DepositState {
    pub(crate) step: DepositStep,
    pub(crate) sk: SecretKey,
}

#[derive(Debug)]
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
