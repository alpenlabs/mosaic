use std::collections::HashMap;

use mosaic_cac_types::{DepositId, MsgId, Seed};

use crate::evaluator::deposit::DepositState;

#[derive(Debug)]
#[expect(dead_code)]
pub struct State<S> {
    pub(crate) config: Option<Config>,
    pub(crate) context: Context,
    pub(crate) step: Step,
    pub(crate) deposits: HashMap<DepositId, DepositState>,
    pub(crate) artifact_store: S,
}

impl<S> State<S> {
    pub fn new_empty(artifact_store: S) -> Self {
        Self {
            config: None,
            context: Context::default(),
            step: Step::Uninit,
            deposits: HashMap::default(),
            artifact_store,
        }
    }
}

/// Immutable state that is set during init and never updated
#[derive(Debug)]
#[expect(dead_code)]
pub struct Config {
    pub(crate) seed: Seed,
}

/// Mutable state that is relevant to multiple steps.
/// This should only hold simple bookkeeping related states.
#[derive(Debug, Default)]
#[expect(dead_code)]
pub struct Context {
    /// ID of commit msg that has accepted and ACK'd.
    pub(crate) ackd_commit_msg_id: Option<MsgId>,
    /// ID of challenge msg that has been sent.
    pub(crate) sent_challenge_msg_id: Option<MsgId>,
    /// ID of challenge response msg that has been accepted and ACK'd.
    pub(crate) ackd_challenge_response_msg_id: Option<MsgId>,
}

/// Valid states.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Step {
    #[default]
    Uninit,
    // TODO: steps
    /// Setup was aborted due to a protocol violation.
    Aborted { reason: String },
}
