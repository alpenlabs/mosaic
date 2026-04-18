//! External event inputs for the garbler state machine.
//!
//! This enum contains only external events — messages received from peers,
//! initialization data from the bridge, and deposit/withdrawal triggers.
//!
//! Action completion results (e.g. `PolynomialCommitmentsGenerated`,
//! `SharesGenerated`, `CommitMsgChunkAcked`) are delivered via FASM's
//! [`TrackedActionCompleted`](fasm::Input::TrackedActionCompleted) mechanism
//! using the [`ActionResult`](super::ActionResult) type. See issue #69.

use crate::{
    AdaptorMsgChunk, ChallengeMsg, DepositId, DepositInputs, PubKey, Seed, SetupInputs, Sighashes,
    TableTransferReceiptMsg, TableTransferRequestMsg, WithdrawalInputs,
};

/// Garbler state machine external event inputs.
///
/// These are events originating from outside the state machine — network
/// messages, bridge triggers, and initialization. They are delivered to the STF
/// via [`fasm::Input::Normal`].
///
/// Action results are **not** included here. When a tracked action completes
/// (e.g. polynomial generation finishes, a message is acked), the result is
/// delivered via [`fasm::Input::TrackedActionCompleted`] with an
/// [`ActionId`](super::ActionId) and [`ActionResult`](super::ActionResult).
#[derive(Debug, Clone)]
pub enum Input {
    /// Initialize the garbler state machine with seed and setup inputs.
    Init(GarblerInitData),

    /// Challenge message received from the evaluator via network.
    RecvChallengeMsg(ChallengeMsg),

    /// Request to transfer a garbling table to evaluator.
    RecvTableTransferRequest(TableTransferRequestMsg),

    /// Receive Table Transfer Receipt
    RecvTableTransferReceipt(TableTransferReceiptMsg),

    /// Initialize a new deposit for the specified deposit ID.
    ///
    /// Triggered externally by the bridge when a transaction graph is generated.
    DepositInit(DepositId, GarblerDepositInitData),

    /// Adaptor message chunk received from the evaluator for this deposit.
    DepositRecvAdaptorMsgChunk(DepositId, AdaptorMsgChunk),

    /// Mark a deposit as withdrawn without dispute.
    ///
    /// The withdrawal completed cooperatively — no need for garbled circuit
    /// evaluation.
    DepositUndisputedWithdrawal(DepositId),

    /// Initiate a disputed withdrawal for this deposit.
    ///
    /// The garbler provides withdrawal input bytes (the proof) which will be
    /// used to complete adaptor signatures and post on-chain.
    DisputedWithdrawal(DepositId, WithdrawalInputs),
}

/// Data required during garbler state machine initialization.
#[derive(Debug, Clone)]
pub struct GarblerInitData {
    /// Seed for deterministic RNG.
    pub seed: Seed,
    /// Setup input wire values.
    pub setup_inputs: SetupInputs,
}

/// Data required to initialize a deposit on the garbler side.
#[derive(Debug, Clone)]
pub struct GarblerDepositInitData {
    /// Public key used to verify adaptors created under evaluator's secret key.
    pub pk: PubKey,
    /// Sighashes to be signed using the adaptors.
    pub sighashes: Sighashes,
    /// Deposit input wire values.
    pub deposit_inputs: DepositInputs,
}
