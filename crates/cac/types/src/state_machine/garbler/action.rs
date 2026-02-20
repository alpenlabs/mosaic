use fasm::actions::TrackedActionTypes;
use mosaic_vs3::Index;

use crate::{
    AllPolynomialCommitments, ChallengeResponseMsgChunk, CircuitInputShares, CircuitOutputShare,
    CommitMsgChunk, CompletedSignatures, DepositAdaptors, DepositId, GarblingSeed,
    GarblingTableCommitment, InputShares, PubKey, ReservedDepositInputShares,
    ReservedWithdrawalInputShares, Seed, Sighashes, WithdrawalAdaptors, WithdrawalInputs,
};

// ============================================================================
// Action ID (lightweight discriminant for tracked action correlation)
// ============================================================================

/// Tracked action identifier for the garbler state machine.
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
    /// Identifies a [`Action::GeneratePolynomialCommitments`] action.
    GeneratePolynomialCommitments(Seed),
    /// Identifies a [`Action::GenerateShares`] action by circuit index.
    GenerateShares(Seed, Index),
    /// Identifies a [`Action::GenerateTableCommitment`] action by circuit index.
    GenerateTableCommitment(Index),
    /// Identifies a [`Action::SendCommitMsgChunk`] action by wire index.
    SendCommitMsgChunk(u16),
    /// Identifies a [`Action::SendChallengeResponseMsgChunk`] action by circuit
    /// index.
    SendChallengeResponseMsgChunk(u16),
    /// Identifies a [`Action::TransferGarblingTable`] action by garbling seed.
    TransferGarblingTable(GarblingSeed),
    /// Identifies a [`Action::DepositVerifyAdaptors`] action by deposit.
    DepositVerifyAdaptors(DepositId),
    /// Identifies a [`Action::CompleteAdaptorSignatures`] action by deposit.
    CompleteAdaptorSignatures(DepositId),
}

impl PartialOrd for ActionId {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        // Discriminant-based ordering; inner values are only compared within
        // the same variant.  This satisfies FASM's PartialOrd bound without
        // requiring PartialOrd on every contained type.
        let self_disc = std::mem::discriminant(self);
        let other_disc = std::mem::discriminant(other);
        // Use debug representation of discriminant for stable ordering.
        format!("{self_disc:?}").partial_cmp(&format!("{other_disc:?}"))
    }
}

// ============================================================================
// Action Result (data returned when a tracked action completes)
// ============================================================================

/// Result of a completed garbler tracked action.
///
/// Delivered to the STF via [`fasm::Input::TrackedActionCompleted`] alongside
/// the corresponding [`ActionId`].
#[derive(Debug)]
#[non_exhaustive]
pub enum ActionResult {
    /// Polynomial commitments were generated from the base seed.
    PolynomialCommitmentsGenerated(AllPolynomialCommitments),
    /// Input and output shares were generated for a circuit.
    SharesGenerated(Index, Box<CircuitInputShares>, Box<CircuitOutputShare>),
    /// Garbling table commitment was generated for a circuit.
    TableCommitmentGenerated(Index, GarblingTableCommitment),
    /// Commit message chunk was sent and acknowledged by the evaluator.
    CommitMsgChunkAcked,
    /// Challenge response chunk was sent and acknowledged by the evaluator.
    ChallengeResponseChunkAcked,
    /// Garbling table was transferred to the evaluator.
    GarblingTableTransferred(GarblingSeed, GarblingTableCommitment),
    /// Adaptor signature verification completed. `bool` indicates pass/fail.
    DepositAdaptorVerificationResult(DepositId, bool),
    /// Adaptor signatures were completed for a disputed withdrawal.
    AdaptorSignaturesCompleted(DepositId, Box<CompletedSignatures>),
}

// ============================================================================
// Actions (unchanged — emitted by the STF for external execution)
// ============================================================================

/// Actions emitted by the garbler state machine for external execution.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Action {
    /// Generate polynomials from the base seed, compute and return commitments.
    /// Polynomials are cached job-side for subsequent [`Self::GenerateShares`] calls.
    GeneratePolynomialCommitments(Seed),
    /// Generate input/output shares by evaluating polynomials at a circuit index.
    /// Reads polynomials from the job-side cache (falls back to regenerating from seed).
    GenerateShares(Seed, Index),
    /// Generate single table's garbling table commitment from seeds and shares.
    GenerateTableCommitment(Index, GarblingSeed),
    /// Send commit message chunk with polynomial commitments for a single wire
    /// to evaluator.
    SendCommitMsgChunk(CommitMsgChunk),
    /// Send challenge response chunk with revealed shares for a single circuit.
    SendChallengeResponseMsgChunk(ChallengeResponseMsgChunk),
    /// Transfer a garbling table to the evaluator.
    TransferGarblingTable(GarblingSeed),

    /// Verify adaptor signatures received from evaluator.
    DepositVerifyAdaptors(DepositId, AdaptorVerificationData),

    /// Complete adaptor signatures for a disputed withdrawal.
    CompleteAdaptorSignatures(DepositId, CompleteAdaptorSignaturesData),
}

impl Action {
    /// Extract the lightweight [`ActionId`] used to correlate this action with
    /// its [`ActionResult`] when it completes.
    pub fn id(&self) -> ActionId {
        match self {
            Self::GeneratePolynomialCommitments(seed) => {
                ActionId::GeneratePolynomialCommitments(*seed)
            }
            Self::GenerateShares(seed, idx) => ActionId::GenerateShares(*seed, *idx),
            Self::GenerateTableCommitment(idx, _) => ActionId::GenerateTableCommitment(*idx),
            Self::SendCommitMsgChunk(chunk) => ActionId::SendCommitMsgChunk(chunk.wire_index),
            Self::SendChallengeResponseMsgChunk(chunk) => {
                ActionId::SendChallengeResponseMsgChunk(chunk.circuit_index)
            }
            Self::TransferGarblingTable(seed) => ActionId::TransferGarblingTable(*seed),
            Self::DepositVerifyAdaptors(id, _) => ActionId::DepositVerifyAdaptors(*id),
            Self::CompleteAdaptorSignatures(id, _) => ActionId::CompleteAdaptorSignatures(*id),
        }
    }
}

// ============================================================================
// Action data types
// ============================================================================

/// Data required to verify adaptor signatures from the evaluator.
#[derive(Debug, PartialEq, Eq)]
pub struct AdaptorVerificationData {
    /// Public key used to verify adaptors created under evaluator's secret key.
    pub pk: PubKey,
    /// Adaptor signatures for deposits.
    pub deposit_adaptors: Box<DepositAdaptors>,
    /// Adaptor signatures for withdrawals.
    pub withdrawal_adaptors: Box<WithdrawalAdaptors>,
    /// Input shares for verification.
    pub input_shares: Box<InputShares>,
    /// Sighashes to verify against.
    pub sighashes: Box<Sighashes>,
}

/// Data required to complete adaptor signatures during a disputed withdrawal.
#[derive(Debug, PartialEq, Eq)]
pub struct CompleteAdaptorSignaturesData {
    /// Public key used to verify adaptors created under evaluator's secret key.
    pub pk: PubKey,
    /// Sighashes to sign.
    pub sighashes: Box<Sighashes>,
    /// Adaptor signatures for deposits.
    pub deposit_adaptors: Box<DepositAdaptors>,
    /// Adaptor signatures for withdrawals.
    pub withdrawal_adaptors: Box<WithdrawalAdaptors>,
    /// Reserved input shares for deposits.
    pub reserved_deposit_input_shares: Box<ReservedDepositInputShares>,
    /// Reserved input shares for withdrawals.
    pub reserved_withdrawal_input_shares: Box<ReservedWithdrawalInputShares>,
    /// Withdrawal input data.
    pub withdrawal_input: Box<WithdrawalInputs>,
}

// ============================================================================
// FASM integration
// ============================================================================

/// Placeholder for untracked actions (currently unused).
#[derive(Debug)]
pub enum UntrackedAction {}

/// Type marker for garbler tracked action types.
///
/// Wires [`ActionId`] and [`ActionResult`] into the FASM framework so that
/// action completions flow through [`fasm::Input::TrackedActionCompleted`]
/// rather than being conflated with external events in the `Input` enum.
#[derive(Debug)]
pub struct GarblerTrackedActionTypes;

impl TrackedActionTypes for GarblerTrackedActionTypes {
    type Id = ActionId;

    type Action = Action;

    type Result = ActionResult;
}

/// Container for garbler actions.
pub type ActionContainer = Vec<fasm::actions::Action<UntrackedAction, GarblerTrackedActionTypes>>;
