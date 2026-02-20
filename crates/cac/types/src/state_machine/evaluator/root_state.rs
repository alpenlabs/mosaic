use mosaic_common::constants::{N_CIRCUITS, N_COMMIT_MSG_CHUNKS, N_EVAL_CIRCUITS, N_OPEN_CIRCUITS};

use crate::{
    ChallengeIndices, DepositId, EvalGarblingTableCommitments, EvaluationIndices, HeapArray,
    OpenedGarblingSeeds, OpenedGarblingTableCommitments, Seed, SetupInputs,
};

/// Evaluator state machine root state.
#[derive(Debug, Clone, Default)]
pub struct EvaluatorState {
    /// Immutable evaluator config set at init.
    pub config: Option<Config>,
    /// Step of the state machine.
    pub step: Step,
}

/// Immutable state that is set during init and never updated
#[derive(Debug, Clone)]
pub struct Config {
    /// Base seed for all deterministic rngs used in this statemachine.
    pub seed: Seed,
    /// Values for input input wires.
    pub setup_inputs: SetupInputs,
}

/// Valid states.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Step {
    #[default]
    /// Not initialized; Default
    Uninit,
    /// Waiting for commit message from garbler.
    WaitingForCommit {
        /// Track if header is received
        header: bool,
        /// Track received commit message chunks
        chunks: HeapArray<bool, N_COMMIT_MSG_CHUNKS>,
    },
    /// Challenge sent, waiting for challenge response from garbler.
    WaitingForChallengeResponse {
        /// Track if header is received
        header: bool,
        /// Track received challenge response chunks
        chunks: HeapArray<bool, N_CIRCUITS>,
    },
    /// Verifying opened input shares from challenge response.
    VerifyingOpenedInputShares,
    /// Verifying opened table commitments match opened seeds.
    VerifyingTableCommitments {
        /// Indices of circuits to verify
        opened_indices: ChallengeIndices,
        /// Seeds for opened circuits
        opened_seeds: OpenedGarblingSeeds,
        /// Commitments for opened circuits
        opened_commitments: OpenedGarblingTableCommitments,
        /// Track verified table commitments
        verified: HeapArray<bool, N_OPEN_CIRCUITS>,
    },
    /// Receiving garbling tables for evaluation circuits.
    ReceivingGarblingTables {
        /// Indices of circuits to evaluate
        eval_indices: EvaluationIndices,
        /// Expected commitments of garbling tables
        eval_commitments: EvalGarblingTableCommitments,
        /// Track received garbling tables
        received: HeapArray<bool, N_EVAL_CIRCUITS>,
    },
    /// Setup is completed, ready to be used for deposits.
    /// Accepts deposit inputs
    SetupComplete,
    /// Evaluating garbling tables for a deposit.
    EvaluatingTables {
        /// Deposit being evaluated
        deposit_id: DepositId,
        /// Indices of circuits to evaluate
        eval_indices: EvaluationIndices,
        /// Expected commitments of garbling tables
        eval_commitments: EvalGarblingTableCommitments,
        /// Track evaluated tables
        evaluated: HeapArray<bool, N_EVAL_CIRCUITS>,
    },
    /// Setup is consumed by a withdrawal dispute. Cannot be reused.
    SetupConsumed {
        /// Disputed withdrawal for deposit
        deposit_id: DepositId,
    },
    /// Setup was aborted due to a protocol violation.
    Aborted {
        /// Abort reason
        reason: String,
    },
}
