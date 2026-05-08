use mosaic_common::constants::{
    N_CHALLENGE_RESPONSE_CHUNKS, N_CIRCUITS, N_COMMIT_MSG_CHUNKS, N_EVAL_CIRCUITS, N_INPUT_WIRES,
};
use serde::{Deserialize, Serialize};

use crate::{
    AllGarblingSeeds, DepositId, EvalGarblingSeeds, EvalGarblingTableCommitments, HeapArray, Seed,
    SetupInputs,
};

/// Default for the per-slot bool arrays that gate `TransferringGarblingTables`
/// progression (see `locally_transferred` / `pending_receipts`). Used as a
/// `#[serde(default)]` fallback so root states persisted before those fields
/// existed deserialize cleanly with all-`false` flags.
fn default_eval_circuits_bool_array() -> HeapArray<bool, N_EVAL_CIRCUITS> {
    HeapArray::from_elem(false)
}

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

crate::state_machine::define_step_phase! {
    StepPhase;
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
            /// Set when our local `TransferGarblingTable` action has reported a
            /// successful completion for this slot. A peer-controlled receipt
            /// only graduates a slot to `transferred` once this flag is set.
            ///
            /// `#[serde(default)]`: pre-existing persisted root states from
            /// before this field was introduced will deserialize with all
            /// flags `false`, which is the conservative starting state for
            /// a slot whose previous transfer history is unknown.
            #[serde(default = "default_eval_circuits_bool_array")]
            locally_transferred: HeapArray<bool, N_EVAL_CIRCUITS>,
            /// Set when a `TableTransferReceiptMsg` arrived for this slot
            /// before `locally_transferred` was true. The SM executor's
            /// job-completion and inbound-network arms run on independent
            /// `select!` branches, so a real evaluator's receipt can reach
            /// the STF before our own local-transfer completion does. We
            /// stash the receipt and graduate the slot to `transferred`
            /// once the matching local-transfer completion also lands.
            ///
            /// `#[serde(default)]` for the same backward-compat reason.
            #[serde(default = "default_eval_circuits_bool_array")]
            pending_receipts: HeapArray<bool, N_EVAL_CIRCUITS>,
            /// Set when both `locally_transferred` and a receipt have been
            /// observed for the slot. `SetupComplete` requires every entry
            /// here to be true.
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
}
