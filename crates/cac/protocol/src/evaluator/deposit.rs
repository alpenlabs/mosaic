use mosaic_cac_types::SecretKey;

#[derive(Debug)]
#[expect(dead_code)]
pub struct DepositState {
    pub(crate) step: DepositStep,
    pub(crate) sk: SecretKey,
}

#[derive(Debug)]
pub enum DepositStep {
    GeneratingAdaptors,
    SendingAdaptors,
    DepositReady,
    WithdrawnUndisputed,
    Aborted { reason: String },
}
