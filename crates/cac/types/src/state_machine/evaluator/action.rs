use fasm::actions::TrackedActionTypes;
use mosaic_vs3::Index;

use crate::{
    AdaptorMsgChunk, ChallengeIndices, ChallengeMsg, CircuitOutputShare, DepositAdaptors,
    DepositId, EvalGarblingTableCommitments, GarblingSeed, GarblingTableCommitment,
    InputPolynomialCommitments, OpenedInputShares, WithdrawalAdaptors,
};

// ============================================================================
// Action ID (lightweight discriminant for tracked action correlation)
// ============================================================================

/// Tracked action identifier for the evaluator state machine.
///
/// Lightweight discriminant used to correlate `TrackedActionCompleted` results
/// with the pending action that produced them. Contains only the minimum data
/// needed to uniquely identify an action within a single SM instance — no heavy
/// payloads.
///
/// Peer ID and role are implicit: each SM instance is scoped to one peer and
/// one role. The SM Executor adds `StateMachineId` when submitting to the
/// Job Scheduler.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ActionId {
    /// Identifies an [`Action::AckCommitMsg`] action.
    AckCommitMsg,
    /// Identifies a [`Action::SendChallengeMsg`] action.
    SendChallengeMsg,
    /// Identifies an [`Action::AckChallengeResponseMsg`] action.
    AckChallengeResponseMsg,
    /// Identifies a [`Action::VerifyOpenedInputShares`] action.
    VerifyOpenedInputShares,
    /// Identifies a [`Action::GenerateTableCommitment`] action by circuit index.
    GenerateTableCommitment(Index),
    /// Identifies a [`Action::ReceiveGarblingTables`] action.
    ReceiveGarblingTables,
    /// Identifies a [`Action::DepositGenerateAdaptors`] action by deposit.
    DepositGenerateAdaptors(DepositId),
    /// Identifies a [`Action::DepositSendAdaptorMsgChunk`] action by deposit
    /// and chunk index.
    DepositSendAdaptorMsgChunk(DepositId, u8),
    /// Identifies a [`Action::EvaluateGarblingTable`] action by circuit index.
    EvaluateGarblingTable(Index),
}

impl PartialOrd for ActionId {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        // Discriminant-based ordering; inner values are only compared within
        // the same variant.  This satisfies FASM's PartialOrd bound without
        // requiring PartialOrd on every contained type.
        let self_disc = std::mem::discriminant(self);
        let other_disc = std::mem::discriminant(other);
        format!("{self_disc:?}").partial_cmp(&format!("{other_disc:?}"))
    }
}

// ============================================================================
// Action Result (data returned when a tracked action completes)
// ============================================================================

/// Result of a completed evaluator tracked action.
///
/// Delivered to the STF via [`fasm::Input::TrackedActionCompleted`] alongside
/// the corresponding [`ActionId`].
#[derive(Debug)]
#[non_exhaustive]
pub enum ActionResult {
    /// Commit message was acknowledged (ack-only, no data).
    CommitMsgAcked,
    /// Challenge message was sent and acknowledged by the garbler.
    ChallengeMsgAcked,
    /// Challenge response message was acknowledged (ack-only, no data).
    ChallengeResponseMsgAcked,
    /// Opened input shares verification completed.
    /// `None` means success; `Some(reason)` means verification failure.
    VerifyOpenedInputSharesResult(Option<String>),
    /// Garbling table commitment was generated for a circuit.
    TableCommitmentGenerated(Index, GarblingTableCommitment),
    /// Garbling table received from garbler and verified.
    GarblingTableReceived(Index, GarblingTableCommitment),
    /// Adaptor signatures were generated for deposit and withdrawal wires.
    DepositAdaptorsGenerated(DepositId, DepositAdaptors, WithdrawalAdaptors),
    /// Adaptor message chunk was sent and acknowledged by the garbler.
    DepositAdaptorMsgAcked(DepositId),
    /// Garbling table evaluation completed.
    /// `None` means no output was produced; `Some` contains the output share.
    TableEvaluationResult(GarblingTableCommitment, Option<CircuitOutputShare>),
}

// ============================================================================
// Actions (unchanged — emitted by the STF for external execution)
// ============================================================================

/// Actions emitted by the evaluator state machine for external execution.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Action {
    /// Acknowledge receipt of commit message from garbler.
    AckCommitMsg,
    /// Send challenge message with set of challenge indices.
    SendChallengeMsg(ChallengeMsg),
    /// Acknowledge receipt of challenge response message from garbler.
    AckChallengeResponseMsg,
    /// Verify opened input shares against polynomial commitments.
    VerifyOpenedInputShares(
        Box<ChallengeIndices>,
        Box<OpenedInputShares>,
        Box<InputPolynomialCommitments>,
    ),
    /// Generate single table's garbling table commitment from seeds and shares.
    GenerateTableCommitment(Index, GarblingSeed),
    /// Receive evaluation garbling tables from garbler.
    ReceiveGarblingTables(EvalGarblingTableCommitments),
    /// Generate adaptors for a deposit.
    DepositGenerateAdaptors(DepositId),
    /// Send adaptor chunk for a deposit to garbler.
    DepositSendAdaptorMsgChunk(DepositId, AdaptorMsgChunk),
    /// Evaluate a single garbling table with provided inputs.
    EvaluateGarblingTable(Index, GarblingTableCommitment),
}

impl Action {
    /// Extract the lightweight [`ActionId`] used to correlate this action with
    /// its [`ActionResult`] when it completes.
    pub fn id(&self) -> ActionId {
        match self {
            Self::AckCommitMsg => ActionId::AckCommitMsg,
            Self::SendChallengeMsg(_) => ActionId::SendChallengeMsg,
            Self::AckChallengeResponseMsg => ActionId::AckChallengeResponseMsg,
            Self::VerifyOpenedInputShares(..) => ActionId::VerifyOpenedInputShares,
            Self::GenerateTableCommitment(idx, _) => ActionId::GenerateTableCommitment(*idx),
            Self::ReceiveGarblingTables(_) => ActionId::ReceiveGarblingTables,
            Self::DepositGenerateAdaptors(id) => ActionId::DepositGenerateAdaptors(*id),
            Self::DepositSendAdaptorMsgChunk(id, chunk) => {
                ActionId::DepositSendAdaptorMsgChunk(*id, chunk.chunk_index)
            }
            Self::EvaluateGarblingTable(idx, _) => ActionId::EvaluateGarblingTable(*idx),
        }
    }
}

// ============================================================================
// FASM integration
// ============================================================================

/// Placeholder for untracked actions (currently unused).
#[derive(Debug)]
pub enum UntrackedAction {}

/// Type marker for evaluator tracked action types.
///
/// Wires [`ActionId`] and [`ActionResult`] into the FASM framework so that
/// action completions flow through [`fasm::Input::TrackedActionCompleted`]
/// rather than being conflated with external events in the `Input` enum.
#[derive(Debug)]
pub struct EvaluatorTrackedActionTypes;

impl TrackedActionTypes for EvaluatorTrackedActionTypes {
    type Id = ActionId;

    type Action = Action;

    type Result = ActionResult;
}

/// Container for evaluator actions.
pub type ActionContainer = Vec<fasm::actions::Action<UntrackedAction, EvaluatorTrackedActionTypes>>;
