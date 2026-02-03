use std::collections::HashMap;

use bitvec::BitArr;
use mosaic_cac_types::{
    ChallengeIndices, DepositId, EvalGarblingTableCommitments, EvaluationIndices,
    OpenedGarblingSeeds, OpenedGarblingTableCommitments, Seed, SetupInputs,
};
use mosaic_common::constants::{
    N_CHALLENGE_RESPONSE_CHUNKS, N_CIRCUITS, N_EVAL_CIRCUITS, N_OPEN_CIRCUITS,
};

use crate::evaluator::deposit::DepositState;

#[derive(Debug)]
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
pub struct Config {
    pub(crate) seed: Seed,
    pub(crate) setup_inputs: SetupInputs,
}

/// Mutable state that is relevant to multiple steps.
/// This should only hold simple bookkeeping related states.
#[derive(Debug, Default)]
pub struct Context {
    /// Commit message was accepted and ACK'd.
    pub(crate) ackd_commit_msg: bool,
    /// Challenge message was sent.
    pub(crate) sent_challenge_msg: bool,
    /// Challenge response message was accepted and ACK'd.
    pub(crate) ackd_challenge_response_msg: bool,
}

/// Valid states.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Step {
    #[default]
    Uninit,
    WaitingForCommit {
        chunks: BitArr!(for N_CIRCUITS),
    },
    WaitingForChallengeResponse {
        chunks: BitArr!(for N_CHALLENGE_RESPONSE_CHUNKS),
    },
    VerifyingOpenedInputShares,
    VerifyingTableCommitments {
        opened_indices: Box<ChallengeIndices>,
        opened_seeds: Box<OpenedGarblingSeeds>,
        opened_commitments: Box<OpenedGarblingTableCommitments>,
        verified: BitArr!(for N_OPEN_CIRCUITS),
    },
    ReceivingGarblingTables {
        eval_indices: EvaluationIndices,
        eval_commitments: EvalGarblingTableCommitments,
        received: BitArr!(for N_EVAL_CIRCUITS),
    },
    SetupComplete,
    EvaluatingTables {
        eval_indices: EvaluationIndices,
        eval_commitments: EvalGarblingTableCommitments,
        evaluated: BitArr!(for N_EVAL_CIRCUITS),
    },
    /// Setup is consumed by a withdrawal dispute. Cannot be reused.
    SetupConsumed {
        /// Disputed withdrawal for deposit
        deposit_id: DepositId,
    },
    /// Setup was aborted due to a protocol violation.
    Aborted {
        reason: String,
    },
}
