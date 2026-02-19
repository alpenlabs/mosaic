use mosaic_cac_types::{
    ChallengeIndices, DepositId, EvalGarblingTableCommitments, EvaluationIndices, HeapArray,
    OpenedGarblingSeeds, OpenedGarblingTableCommitments, Seed, SetupInputs,
};
use mosaic_common::constants::{N_CIRCUITS, N_COMMIT_MSG_CHUNKS, N_EVAL_CIRCUITS, N_OPEN_CIRCUITS};

use crate::StateContainer;

pub type EvaluatorStateContainer<S> = StateContainer<EvaluatorState, S>;

#[derive(Debug, Default)]
pub struct EvaluatorState {
    pub(crate) config: Option<Config>,
    pub(crate) step: Step,
}

impl EvaluatorState {
    /// Initialize to an empty state.
    pub fn init_empty() -> Self {
        Self {
            config: None,
            step: Step::Uninit,
        }
    }
}

/// Immutable state that is set during init and never updated
#[derive(Debug)]
pub struct Config {
    pub(crate) seed: Seed,
    pub(crate) setup_inputs: SetupInputs,
}

/// Valid states.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Step {
    #[default]
    Uninit,
    WaitingForCommit {
        header: bool,
        chunks: HeapArray<bool, N_COMMIT_MSG_CHUNKS>,
    },
    WaitingForChallengeResponse {
        header: bool,
        chunks: HeapArray<bool, N_CIRCUITS>,
    },
    VerifyingOpenedInputShares,
    VerifyingTableCommitments {
        opened_indices: ChallengeIndices,
        opened_seeds: OpenedGarblingSeeds,
        opened_commitments: Box<OpenedGarblingTableCommitments>,
        verified: HeapArray<bool, N_OPEN_CIRCUITS>,
    },
    ReceivingGarblingTables {
        eval_indices: EvaluationIndices,
        eval_commitments: EvalGarblingTableCommitments,
        received: HeapArray<bool, N_EVAL_CIRCUITS>,
    },
    SetupComplete,
    EvaluatingTables {
        deposit_id: DepositId,
        eval_indices: EvaluationIndices,
        eval_commitments: EvalGarblingTableCommitments,
        evaluated: HeapArray<bool, N_EVAL_CIRCUITS>,
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
