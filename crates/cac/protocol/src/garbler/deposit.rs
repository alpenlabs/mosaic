use mosaic_cac_types::{MsgId, PubKey};

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
    pub ackd_adaptor_msg_id: Option<MsgId>,
}

impl DepositState {
    pub(crate) fn init(pk: PubKey) -> Self {
        Self {
            step: DepositStep::WaitingForAdaptors,
            pk,
            ackd_adaptor_msg_id: None,
        }
    }
}
