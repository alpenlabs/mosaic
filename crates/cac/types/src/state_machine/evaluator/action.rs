use fasm::actions::TrackedActionTypes;
use mosaic_vs3::Index;

use crate::{
    AdaptorMsg, ChallengeIndices, ChallengeMsg, CircuitInputShares, DepositId,
    EvalGarblingTableCommitments, GarblingSeed, GarblingTableCommitment,
    InputPolynomialCommitments, MsgId, OpenedInputShares,
};

/// Actions emitted by the evaluator state machine for external execution.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Action {
    /// Acknowledge receipt of commit message from garbler.
    AckCommitMsg(MsgId),
    /// Send challenge message with set of challenge indices.
    SendChallengeMsg(ChallengeMsg),
    /// Acknowledge receipt of challenge response message from garbler.
    AckChallengeResponseMsg(MsgId),
    /// Verify opened input shares against polynomial commitments.
    VerifyOpenedInputShares(
        Box<ChallengeIndices>,
        Box<OpenedInputShares>,
        Box<InputPolynomialCommitments>,
    ),
    /// Generate single table's garbling table commitment from seeds and shares.
    GenerateTableCommitment(Index, GarblingSeed),
    /// Receive evaluation garbling tables from garbler.
    ReceiveGarblingTables(Box<EvalGarblingTableCommitments>),
    /// Generate adaptors for a deposit.
    DepositGenerateAdaptors(DepositId),
    /// Send adaptors for a deposit to garbler.
    DepositSendAdaptorMsg(DepositId, AdaptorMsg),
    /// Evaluate a single garbling table with provided inputs
    EvaluateGarblingTable(GarblingTableCommitment, Box<CircuitInputShares>),
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
