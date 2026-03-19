use mosaic_common::constants::{
    N_CHALLENGE_RESPONSE_CHUNKS, N_CIRCUITS, N_COMMIT_MSG_CHUNKS, N_EVAL_CIRCUITS, N_INPUT_WIRES,
};
use serde::{Deserialize, Serialize};

use crate::{
    AllGarblingSeeds, DepositId, EvalGarblingSeeds, EvalGarblingTableCommitments, HeapArray, Seed,
    SetupInputs,
};

/// Root state for the garbler in the setup protocol.
///
/// Contains the configuration and current step in the protocol state machine.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GarblerState {
    /// Immutable garbler config set at init.
    pub config: Option<Config>,
    /// Current step in the state machine.
    pub step: Step,
}

/// Immutable state that is set during init and never updated
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    /// Seed for deterministic rng.
    pub seed: Seed,
    /// Values for setup input wires.
    pub setup_inputs: SetupInputs,
}

/// Valid states.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Step {
    #[default]
    /// Not initialized; Default
    Uninit,
    /// Polynomials generated.
    GeneratingPolynomialCommitments {
        /// Track generated input polynomial commitments.
        inputs: HeapArray<bool, N_INPUT_WIRES>,
        /// Track whether output polynomial commitment has been generated.
        output: bool,
    },
    /// Generate shares for all tables.
    GeneratingShares {
        /// Track which shares have been generated.
        generated: HeapArray<bool, { N_CIRCUITS + 1 }>,
    },
    /// Dispatch actions to generate commitments.
    /// Wait for all table commitments to be provided.
    GeneratingTableCommitments {
        /// Seeds for all garbling operations.
        seeds: AllGarblingSeeds,
        /// Track which table commitments have been generated.
        generated: HeapArray<bool, N_CIRCUITS>,
    },
    /// Got table commitments, sending commit msg chunks.
    /// Transitions to WaitingForChallenge when all chunks are acked.
    SendingCommit {
        /// Track ack of commit msg header.
        header_acked: bool,
        /// Track which commit msg chunks have been acked.
        chunk_acked: HeapArray<bool, N_COMMIT_MSG_CHUNKS>,
    },
    /// All commit chunks acked, waiting for challenge msg from evaluator.
    WaitingForChallenge,
    /// Sending challenge response chunks. Transitions to
    /// TransferringGarblingTables when all chunks are acked.
    SendingChallengeResponse {
        /// Track ack of challenge response header.
        header_acked: bool,
        /// Track which challenge response chunks have been acked.
        chunk_acked: HeapArray<bool, N_CHALLENGE_RESPONSE_CHUNKS>,
    },
    /// Challenge response msg ack received, send garbling tables
    TransferringGarblingTables {
        /// Seeds for garbling table generation
        eval_seeds: EvalGarblingSeeds,
        /// Expected commitments of garbling tables, for sanity
        eval_commitments: EvalGarblingTableCommitments,
        /// Track transferred garbling tables
        transferred: HeapArray<bool, N_EVAL_CIRCUITS>,
    },
    /// Wait For Table Transfer Receipt
    WaitForTableTransferReceipt {
        /// acked table index
        acked_indices: HeapArray<bool, N_EVAL_CIRCUITS>,
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

impl Step {
    /// Name of step
    pub fn step_name(&self) -> &'static str {
        match self {
            Step::Uninit => "Uninit",
            Step::GeneratingPolynomialCommitments { .. } => "GeneratingPolynomialCommitments",
            Step::GeneratingShares { .. } => "GeneratingShares",
            Step::GeneratingTableCommitments { .. } => "GeneratingTableCommitments",
            Step::SendingCommit { .. } => "SendingCommit",
            Step::WaitingForChallenge => "WaitingForChallenge",
            Step::SendingChallengeResponse { .. } => "SendingChallengeResponse",
            Step::TransferringGarblingTables { .. } => "TransferringGarblingTables",
            Step::WaitForTableTransferReceipt { .. } => "WaitForTableTransferReceipt",
            Step::SetupComplete => "SetupComplete",
            Step::CompletingAdaptors { .. } => "CompletingAdaptors",
            Step::SetupConsumed { .. } => "SetupConsumed",
            Step::Aborted { .. } => "Aborted",
        }
    }
}
