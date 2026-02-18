use std::collections::HashMap;

use mosaic_cac_types::{
    AllGarblingSeeds, DepositId, EvalGarblingSeeds, EvalGarblingTableCommitments, HeapArray, Seed,
    SetupInputs,
};
use mosaic_common::constants::{
    N_CHALLENGE_RESPONSE_CHUNKS, N_CIRCUITS, N_COMMIT_MSG_CHUNKS, N_EVAL_CIRCUITS,
};

use super::deposit::DepositState;
use crate::StateContainer;

pub type GarblerStateContainer<S> = StateContainer<GarblerState, S>;

#[derive(Debug, Clone, Default)]
pub struct GarblerState {
    pub(crate) config: Option<Config>,
    pub(crate) step: Step,
    pub(crate) deposits: HashMap<DepositId, DepositState>,
}

impl GarblerState {
    /// Initialize to an empty state.
    pub fn init_empty() -> Self {
        Self {
            config: None,
            step: Step::Uninit,
            deposits: HashMap::new(),
        }
    }

    pub fn step_mut(&mut self) -> &mut Step {
        &mut self.step
    }
}

/// Immutable state that is set during init and never updated
#[derive(Debug, Clone, Copy)]
pub struct Config {
    pub(crate) seed: Seed,
    pub(crate) setup_inputs: SetupInputs,
}

/// Valid states.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Step {
    #[default]
    /// Not initialized; Default
    Uninit,
    /// Polynomials generated.
    GeneratingPolynomialCommitments,
    /// Generate shares for all tables.
    GeneratingShares {
        generated: HeapArray<bool, N_CIRCUITS>,
    },
    /// Dispatch actions to generate commitments.
    /// Wait for all table commitments to be provided.
    GeneratingTableCommitments {
        seeds: Box<AllGarblingSeeds>,
        generated: HeapArray<bool, N_CIRCUITS>,
    },
    /// Got table commitments, sending commit msg chunks.
    /// Transitions to WaitingForChallenge when all chunks are acked.
    SendingCommit {
        /// Track which commit msg chunks have been acked.
        acked: HeapArray<bool, N_COMMIT_MSG_CHUNKS>,
    },
    /// All commit chunks acked, waiting for challenge msg from evaluator.
    WaitingForChallenge,
    /// Sending challenge response chunks. Transitions to
    /// TransferringGarblingTables when all chunks are acked.
    SendingChallengeResponse {
        /// Track which challenge response chunks have been acked.
        acked: HeapArray<bool, N_CHALLENGE_RESPONSE_CHUNKS>,
    },
    /// Challenge response msg ack received, send garbling tables
    TransferringGarblingTables {
        /// Seeds for garbling table generation
        eval_seeds: Box<EvalGarblingSeeds>,
        /// Expected commitments of garbling tables, for sanity
        eval_commitments: Box<EvalGarblingTableCommitments>,
        /// Track transferred garbling tables
        transferred: HeapArray<bool, N_EVAL_CIRCUITS>,
    },
    /// Setup is completed, ready to be used for deposits.
    /// Accepts deposit inputs
    SetupComplete,
    /// Disputed Withdrawal is triggered.
    /// Compleing adaptor sigs.
    CompletingAdaptors {
        /// Disputed withdrawal for deposit
        deposit_id: DepositId,
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
