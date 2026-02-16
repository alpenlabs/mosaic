use bitvec::BitArr;
use mosaic_cac_types::PubKey;
use mosaic_common::constants::N_ADAPTOR_MSG_CHUNKS;

#[derive(Debug, Clone)]
pub enum DepositStep {
    WaitingForAdaptors {
        chunks: BitArr!(for N_ADAPTOR_MSG_CHUNKS),
    },
    VerifyingAdaptors,
    DepositReady,
    WithdrawnUndisputed,
    Aborted {
        reason: String,
    },
}

#[derive(Debug, Clone)]
pub struct DepositState {
    pub step: DepositStep,
    pub pk: PubKey,
}
