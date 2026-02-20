use mosaic_cac_types::{HeapArray, PubKey};
use mosaic_common::constants::N_ADAPTOR_MSG_CHUNKS;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DepositStep {
    WaitingForAdaptors {
        chunks: HeapArray<bool, N_ADAPTOR_MSG_CHUNKS>,
    },
    VerifyingAdaptors,
    DepositReady,
    WithdrawnUndisputed,
    Aborted {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepositState {
    pub step: DepositStep,
    pub pk: PubKey,
}
