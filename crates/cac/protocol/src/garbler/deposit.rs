use mosaic_cac_types::PubKey;

#[derive(Debug)]
pub enum DepositStep {
    WaitingForAdaptors,
    VerifyingAdaptors,
    DepositReady,
    WithdrawnUndisputed,
    Aborted { reason: String },
}

#[derive(Debug)]
pub struct DepositState {
    pub step: DepositStep,
    pub pk: PubKey,
}

impl DepositState {
    pub(crate) fn init(pk: PubKey) -> Self {
        Self {
            step: DepositStep::WaitingForAdaptors,
            pk,
        }
    }
}
