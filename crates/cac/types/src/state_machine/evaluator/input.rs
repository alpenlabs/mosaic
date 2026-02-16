//! External event inputs for the evaluator state machine.
//!
//! This enum contains only external events — messages received from peers,
//! initialization data from the bridge, and deposit/withdrawal triggers.
//!
//! Action completion results (e.g. `ChallengeMsgAcked`,
//! `VerifyOpenedInputSharesResult`, `TableEvaluationResult`) are delivered via
//! FASM's [`TrackedActionCompleted`](fasm::Input::TrackedActionCompleted)
//! mechanism using the [`ActionResult`](super::ActionResult) type. See issue
//! #69.

use crate::{
    ChallengeResponseMsgChunk, ChallengeResponseMsgHeader, CommitMsgChunk, CommitMsgHeader,
    CompletedSignatures, DepositId, DepositInputs, SecretKey, Seed, SetupInputs, Sighashes,
    WithdrawalInputs,
};

/// Evaluator state machine external event inputs.
///
/// These are events originating from outside the state machine — network
/// messages, bridge triggers, and initialization. They are delivered to the STF
/// via [`fasm::Input::Normal`].
///
/// Action results are **not** included here. When a tracked action completes
/// (e.g. challenge message is acked, verification finishes), the result is
/// delivered via [`fasm::Input::TrackedActionCompleted`] with an
/// [`ActionId`](super::ActionId) and [`ActionResult`](super::ActionResult).
#[derive(Debug)]
#[non_exhaustive]
pub enum Input {
    /// Initialize the evaluator state machine with seed and setup inputs.
    Init(EvaluatorInitData),

    /// Commit message header received from the garbler via network.
    RecvCommitMsgHeader(CommitMsgHeader),

    /// Commit message chunk received from the garbler via network.
    RecvCommitMsgChunk(CommitMsgChunk),

    /// Challenge response message header received from the garbler via network.
    RecvChallengeResponseMsgHeader(ChallengeResponseMsgHeader),

    /// Challenge response message chunk received from the garbler via network.
    RecvChallengeResponseMsgChunk(ChallengeResponseMsgChunk),

    /// Initialize a new deposit for the specified deposit ID.
    ///
    /// Triggered externally by the bridge when a transaction graph is generated.
    DepositInit(DepositId, EvaluatorDepositInitData),

    /// Mark a deposit as withdrawn without dispute.
    ///
    /// The withdrawal completed cooperatively — no need for garbled circuit
    /// evaluation.
    DepositUndisputedWithdrawal(DepositId),

    /// Initiate a disputed withdrawal for this deposit.
    ///
    /// The evaluator receives completed signatures from the on-chain
    /// transaction, extracts input shares, and evaluates garbling tables to
    /// reveal the fault secret.
    DisputedWithdrawal(DepositId, EvaluatorDisputedWithdrawalData),
}

/// Data required during evaluator state machine initialization.
#[derive(Debug)]
pub struct EvaluatorInitData {
    /// Seed for deterministic RNG.
    pub seed: Seed,
    /// Setup input wire values.
    pub setup_inputs: SetupInputs,
}

/// Data required to initialize a deposit on the evaluator side.
#[derive(Debug)]
pub struct EvaluatorDepositInitData {
    /// Secret key used to generate adaptors.
    pub sk: SecretKey,
    /// Sighashes to be signed using the adaptors.
    pub sighashes: Box<Sighashes>,
    /// Deposit input wire values.
    pub deposit_inputs: Box<DepositInputs>,
}

/// Data required to initiate a disputed withdrawal process.
#[derive(Debug)]
pub struct EvaluatorDisputedWithdrawalData {
    /// Withdrawal input wire values.
    // NOTE: this might not be required
    pub withdrawal_inputs: Box<WithdrawalInputs>,
    /// Completed adaptor signatures extracted from on-chain transaction.
    pub signatures: Box<CompletedSignatures>,
}
