use mosaic_cac_types::{MsgId, SecretKey};

#[derive(Debug)]
#[expect(dead_code)]
pub struct DepositState {
    pub(crate) step: DepositStep,
    pub(crate) sk: SecretKey,
    pub(crate) sent_adaptor_msg_id: Option<MsgId>,
}

#[derive(Debug)]
pub enum DepositStep {
    GeneratingAdaptors,
    SendingAdaptors,
    DepositReady,
    WithdrawnUndisputed,
    Aborted { reason: String },
}
