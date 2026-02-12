use bitvec::BitArr;
use mosaic_cac_types::SecretKey;
use mosaic_common::constants::N_ADAPTOR_MSG_CHUNKS;

#[derive(Debug)]
#[expect(dead_code)]
pub struct DepositState {
    pub(crate) step: DepositStep,
    pub(crate) sk: SecretKey,
}

#[derive(Debug)]
pub enum DepositStep {
    GeneratingAdaptors,
    /// Sending adaptor message chunks to the garbler.
    /// Transitions to `DepositReady` when all chunks are acked.
    SendingAdaptors {
        /// Track which adaptor message chunks have been acked.
        acked: BitArr!(for N_ADAPTOR_MSG_CHUNKS),
    },
    DepositReady,
    WithdrawnUndisputed,
    Aborted {
        reason: String,
    },
}
