//! Domain types for the service layer.
//!
//! These are transport-agnostic representations of service responses and
//! configuration, using domain types from `mosaic-cac-types`.

use bitcoin::{XOnlyPublicKey, secp256k1::schnorr::Signature as SchnorrSignature};
use mosaic_cac_types::{
    DepositId, DepositInputs, SetupInputs, Sighashes, WithdrawalInputs,
    state_machine::{
        Role,
        evaluator::{self},
        garbler::{self},
    },
};
use mosaic_common::Byte32;
use mosaic_net_svc_api::PeerId;

/// Status of a tableset (state machine).
#[derive(Debug, Clone)]
pub enum TablesetStatus {
    /// Setup protocol is in progress.
    Incomplete {
        /// Step name for debugging.
        details: String,
    },

    /// Setup completed, ready for deposits.
    SetupComplete,

    /// Contested withdrawal in progress.
    Contest {
        /// Deposit involved in the contest.
        deposit_id: DepositId,
    },

    /// Setup consumed by a contested withdrawal.
    Consumed {
        /// Deposit that consumed the setup.
        deposit_id: DepositId,
        /// Whether the fault secret was successfully extracted (evaluator only).
        success: bool,
    },

    /// Setup aborted due to protocol violation.
    Aborted {
        /// Reason for abort.
        reason: String,
    },
}

/// Status of a deposit.
#[derive(Debug, Clone)]
pub enum DepositStatus {
    /// Deposit setup in progress.
    Incomplete {
        /// Step name for debugging.
        details: String,
    },

    /// Deposit ready for withdrawal.
    Ready,

    /// Deposit withdrawn without dispute.
    UncontestedWithdrawal,

    /// Another deposit consumed this tableset's setup.
    Consumed {
        /// Deposit that consumed the setup.
        by: DepositId,
    },

    /// Deposit aborted due to protocol violation.
    Aborted {
        /// Reason for abort.
        reason: String,
    },
}

/// Deposit ID paired with its status.
#[derive(Debug, Clone)]
pub struct DepositWithStatus {
    /// Deposit identifier.
    pub deposit_id: DepositId,
    /// Current status.
    pub status: DepositStatus,
}

/// Configuration for setting up a new tableset.
#[derive(Debug, Clone)]
pub struct SetupConfig {
    /// Role in the protocol.
    pub role: Role,
    /// Peer to set up with.
    pub peer_id: PeerId,
    /// Setup input wire values.
    pub setup_inputs: SetupInputs,
    /// Instance ID (for multiple tablesets per peer pair).
    pub instance: Byte32,
}

/// Configuration for initializing a garbler deposit.
#[derive(Debug)]
pub struct GarblerDepositInit {
    /// Evaluator's adaptor public key (BIP-340 x-only).
    pub adaptor_pk: XOnlyPublicKey,
    /// Sighashes for deposit and withdrawal inputs.
    pub sighashes: Sighashes,
    /// Deposit input wire values.
    pub deposit_inputs: DepositInputs,
}

/// Configuration for initializing an evaluator deposit.
#[derive(Debug)]
pub struct EvaluatorDepositInit {
    /// Sighashes for deposit and withdrawal inputs.
    pub sighashes: Sighashes,
    /// Deposit input wire values.
    pub deposit_inputs: DepositInputs,
}

/// Data for an evaluator contested withdrawal.
#[derive(Debug)]
pub struct EvaluatorWithdrawalData {
    /// Withdrawal input wire values.
    pub withdrawal_inputs: WithdrawalInputs,
    /// Completed adaptor signatures from the garbler (bitcoin Schnorr format).
    pub signatures: Vec<SchnorrSignature>,
}

// --- From impls: garbler/evaluator state -> service domain types ---

impl From<&garbler::Step> for TablesetStatus {
    fn from(step: &garbler::Step) -> Self {
        use garbler::Step::*;
        match step {
            Uninit
            | GeneratingPolynomialCommitments { .. }
            | GeneratingShares { .. }
            | GeneratingTableCommitments { .. }
            | SendingCommit { .. }
            | WaitingForChallenge
            | SendingChallengeResponse { .. }
            | TransferringGarblingTables { .. } => TablesetStatus::Incomplete {
                details: step.step_name().into(),
            },
            SetupComplete => TablesetStatus::SetupComplete,
            CompletingAdaptors { deposit_id } => TablesetStatus::Contest {
                deposit_id: *deposit_id,
            },
            SetupConsumed { deposit_id } => TablesetStatus::Consumed {
                deposit_id: *deposit_id,
                success: true,
            },
            Aborted { reason } => TablesetStatus::Aborted {
                reason: reason.clone(),
            },
        }
    }
}

impl From<&evaluator::Step> for TablesetStatus {
    fn from(step: &evaluator::Step) -> Self {
        use evaluator::Step::*;
        match step {
            Uninit
            | WaitingForCommit { .. }
            | WaitingForChallengeResponse { .. }
            | VerifyingOpenedInputShares
            | VerifyingTableCommitments { .. }
            | ReceivingGarblingTables { .. } => TablesetStatus::Incomplete {
                details: step.step_name().into(),
            },
            SetupComplete => TablesetStatus::SetupComplete,
            EvaluatingTables { deposit_id, .. } => TablesetStatus::Contest {
                deposit_id: *deposit_id,
            },
            SetupConsumed {
                deposit_id,
                success,
            } => TablesetStatus::Consumed {
                deposit_id: *deposit_id,
                success: *success,
            },
            Aborted { reason } => TablesetStatus::Aborted {
                reason: reason.clone(),
            },
        }
    }
}

impl From<garbler::DepositState> for DepositStatus {
    fn from(deposit: garbler::DepositState) -> Self {
        match deposit.step {
            garbler::DepositStep::WaitingForAdaptors { .. }
            | garbler::DepositStep::VerifyingAdaptors => DepositStatus::Incomplete {
                details: deposit.step.step_name().into(),
            },
            garbler::DepositStep::DepositReady => DepositStatus::Ready,
            garbler::DepositStep::WithdrawnUndisputed => DepositStatus::UncontestedWithdrawal,
            garbler::DepositStep::Aborted { reason } => DepositStatus::Aborted { reason },
        }
    }
}

impl From<evaluator::DepositState> for DepositStatus {
    fn from(deposit: evaluator::DepositState) -> Self {
        match deposit.step {
            evaluator::DepositStep::GeneratingAdaptors { .. }
            | evaluator::DepositStep::SendingAdaptors { .. } => DepositStatus::Incomplete {
                details: deposit.step.step_name().into(),
            },
            evaluator::DepositStep::DepositReady => DepositStatus::Ready,
            evaluator::DepositStep::WithdrawnUndisputed => DepositStatus::UncontestedWithdrawal,
            evaluator::DepositStep::Aborted { reason } => DepositStatus::Aborted { reason },
        }
    }
}
