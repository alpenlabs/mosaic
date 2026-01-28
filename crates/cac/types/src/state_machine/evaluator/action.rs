use fasm::actions::TrackedActionTypes;
use mosaic_vs3::Index;

#[allow(unused_imports, reason = "docs")]
use crate::state_machine::{evaluator, garbler};
use crate::{
    AdaptorMsg, ChallengeIndices, ChallengeMsg, DepositId, GarblingSeed, GarblingTableCommitment,
    MsgId,
};

/// Actions emitted by the evaluator state machine for external execution.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Action {
    /// Acknowledge receipt of commit message from garbler.
    /// Result: [`garbler::Input::CommitMsgAcked`] on garbler
    AckCommitMsg(MsgId),
    /// Send challenge message with set of challenge indices.
    /// Result: [`garbler::Input::RecvChallengeMsg`] on garbler
    SendChallengeMsg(ChallengeMsg),
    /// Acknowledge receipt of challenge response message from garbler.
    /// Result: [`garbler::Input::ChallengeResponseAcked`] on garbler
    AckChallengeResponseMsg(MsgId),
    /// Verify opened input shares against polynomial commitments.
    /// Result: [`evaluator::Input::VerifyOpenedInputSharesResult`]
    VerifyOpenedInputShares(Box<ChallengeIndices>),
    /// Generate single table's garbling table commitment from seeds and shares.
    /// Result: [`evaluator::Input::TableCommitmentGenerated`]
    GenerateTableCommitment(Index, GarblingSeed),
    /// Receive evaluation garbling table identified by a specific commitment from garbler.
    /// Result: [`evaluator::Input::GarblingTableReceived`]
    AcceptGarblingTableTransfer(GarblingTableCommitment),

    /// Generate adaptors for a deposit.
    /// Result: [`evaluator::Input::DepositAdaptorsGenerated`]
    DepositGenerateAdaptors(DepositId),
    /// Send adaptors for a deposit to garbler.
    /// Result: [`garbler::Input::DepositRecvAdaptorMsg`] on garbler
    DepositSendAdaptorMsg(DepositId, AdaptorMsg),

    /// Evaluate a single garbling table with provided inputs
    /// Result: [`evaluator::Input::TableEvaluationResult`]
    EvaluateGarblingTable(Index, GarblingTableCommitment),
}

/// Placeholder for untracked actions (currently unused).
#[derive(Debug)]
pub enum UntrackedAction {}

/// Type marker for evaluator tracked action types.
#[derive(Debug)]
pub struct EvaluatorTrackedActionTypes;

impl TrackedActionTypes for EvaluatorTrackedActionTypes {
    type Id = ();

    type Action = Action;

    type Result = ();
}

/// Container for evaluator actions.
pub type ActionContainer = Vec<fasm::actions::Action<UntrackedAction, EvaluatorTrackedActionTypes>>;
