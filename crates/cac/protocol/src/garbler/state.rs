use std::collections::HashMap;

use bitvec::BitArr;
use mosaic_cac_types::{
    AllGarblingSeeds, DepositId, EvalGarblingSeeds, EvalGarblingTableCommitments, MsgId, Seed,
    SetupInputs,
};
use mosaic_common::constants::{N_CIRCUITS, N_EVAL_CIRCUITS};

use super::deposit::DepositState;

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
            deposits: HashMap::new(),
            artifact_store,
        }
    }
}

/// Immutable state that is set during init and never updated
#[derive(Debug, Clone, Copy)]
pub struct Config {
    pub(crate) seed: Seed,
    pub(crate) setup_inputs: SetupInputs,
}

/// Mutable state that is relevant to multiple steps.
/// This should only hold simple bookkeeping related states.
#[derive(Debug, Default)]
pub struct Context {
    /// ID of commit msg that has been sent.
    pub(crate) sent_commit_msg_id: Option<MsgId>,
    /// ID of challenge msg that has been accepted and ACK'd.
    pub(crate) ackd_challenge_msg_id: Option<MsgId>,
    /// ID of challenge response msg that has been sent.
    pub(crate) sent_challenge_response_msg_id: Option<MsgId>,
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
    GeneratingShares { generated: BitArr!(for N_CIRCUITS) },
    /// Dispatch actions to generate commitments.
    /// Wait for all table commitments to be provided.
    GeneratingTableCommitments {
        seeds: Box<AllGarblingSeeds>,
        generated: BitArr!(for N_CIRCUITS),
    },
    /// Got table commitments, send commit msg.
    /// Wait for commit msg ack.
    SendingCommit,
    /// Wait for challenge msg
    WaitingForChallenge,
    /// Send challenge response and wait for ack.
    SendingChallengeResponse,
    /// Challenge response msg ack received, send garbling tables
    TransferringGarblingTables {
        /// Seeds for garbling table generation
        eval_seeds: Box<EvalGarblingSeeds>,
        /// Expected commitments of garbling tables, for sanity
        eval_commitments: Box<EvalGarblingTableCommitments>,
        /// Track transferred garbling tables
        transferred: BitArr!(for N_EVAL_CIRCUITS),
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
