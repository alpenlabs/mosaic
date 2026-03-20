use fasm::actions::TrackedActionTypes;
use mosaic_common::Byte32;
use mosaic_vs3::Index;

use crate::{
    ChallengeResponseMsgChunk, ChallengeResponseMsgHeader, CircuitInputShares, CircuitOutputShare,
    CommitMsgHeader, CompletedSignatures, DepositId, GarblingSeed, GarblingTableCommitment,
    OutputPolynomialCommitment, Seed, WideLabelWirePolynomialCommitments,
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
    GeneratePolynomialCommitments(Seed, Wire),
    /// Identifies a [`Action::GenerateShares`] action by circuit index.
    GenerateShares(Seed, Index),
    /// Identifies a [`Action::GenerateTableCommitment`] action by circuit index.
    GenerateTableCommitment(Index),
    /// Identifies a [`Action::SendCommitMsgHeader`] action.
    SendCommitMsgHeader,
    /// Identifies a [`Action::SendCommitMsgChunk`] action by wire index.
    SendCommitMsgChunk(u16),
    /// Identifies a [`Action::SendChallengeResponseMsgHeader`] action.
    SendChallengeResponseMsgHeader,
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
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ActionResult {
    /// Polynomial commitments were generated from the base seed.
    PolynomialCommitmentsGenerated(GeneratedPolynomialCommitments),
    /// Input and output shares were generated for a circuit.
    SharesGenerated(Index, CircuitInputShares, CircuitOutputShare),
    /// Garbling table commitment was generated for a circuit, along with
    /// garbling metadata needed for [`CommitMsgHeader`] construction.
    TableCommitmentGenerated(Index, GarblingTableCommitment, GarblingMetadata),
    /// Commit message header was sent and acknowledged by the evaluator.
    CommitMsgHeaderAcked,
    /// Commit message chunk was sent and acknowledged by the evaluator.
    CommitMsgChunkAcked,
    /// Challenge response message header was sent and acknowledged by the evaluator.
    ChallengeResponseHeaderAcked,
    /// Challenge response chunk was sent and acknowledged by the evaluator.
    ChallengeResponseChunkAcked,
    /// Garbling table was transferred to the evaluator.
    GarblingTableTransferred(GarblingSeed, GarblingTableCommitment),
    /// Adaptor signature verification completed. `bool` indicates pass/fail.
    DepositAdaptorVerificationResult(DepositId, bool),
    /// Adaptor signatures were completed for a disputed withdrawal.
    AdaptorSignaturesCompleted(DepositId, CompletedSignatures),
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
    GeneratePolynomialCommitments(Seed, Wire),
    /// Generate input/output shares by evaluating polynomials at a circuit index.
    /// Reads polynomials from the job-side cache (falls back to regenerating from seed).
    GenerateShares(Seed, Index),
    /// Generate single table's garbling table commitment from seeds and shares.
    GenerateTableCommitment(Index, GarblingSeed),
    /// Send commit message header with garbling table commitments and output polynomial commitment.
    SendCommitMsgHeader(CommitMsgHeader),
    /// Send commit message chunk for specified wire inded to evaluator.
    SendCommitMsgChunk(u16),
    /// Send challenge response header with setup input shares, output shares and garbling seeds for
    /// opened circuits.
    SendChallengeResponseMsgHeader(ChallengeResponseMsgHeader),
    /// Send challenge response chunk with revealed shares for a single circuit.
    SendChallengeResponseMsgChunk(ChallengeResponseMsgChunk),
    /// Transfer a garbling table to the evaluator.
    TransferGarblingTable(GarblingSeed),

    /// Verify adaptor signatures received from evaluator.
    DepositVerifyAdaptors(DepositId),

    /// Complete adaptor signatures for a disputed withdrawal.
    CompleteAdaptorSignatures(DepositId),
}

impl Action {
    /// Extract the lightweight [`ActionId`] used to correlate this action with
    /// its [`ActionResult`] when it completes.
    pub fn id(&self) -> ActionId {
        match self {
            Self::GeneratePolynomialCommitments(seed, wire) => {
                ActionId::GeneratePolynomialCommitments(*seed, *wire)
            }
            Self::GenerateShares(seed, idx) => ActionId::GenerateShares(*seed, *idx),
            Self::GenerateTableCommitment(idx, _) => ActionId::GenerateTableCommitment(*idx),
            Self::SendCommitMsgHeader(_) => ActionId::SendCommitMsgHeader,
            Self::SendCommitMsgChunk(wire_idx) => ActionId::SendCommitMsgChunk(*wire_idx),
            Self::SendChallengeResponseMsgHeader(_) => ActionId::SendChallengeResponseMsgHeader,
            Self::SendChallengeResponseMsgChunk(chunk) => {
                ActionId::SendChallengeResponseMsgChunk(chunk.circuit_index)
            }
            Self::TransferGarblingTable(seed) => ActionId::TransferGarblingTable(*seed),
            Self::DepositVerifyAdaptors(id) => ActionId::DepositVerifyAdaptors(*id),
            Self::CompleteAdaptorSignatures(id) => ActionId::CompleteAdaptorSignatures(*id),
        }
    }
}

// ============================================================================
// Action data types
// ============================================================================

/// Metadata from a garbling session needed for [`CommitMsgHeader`] construction.
///
/// Produced by the job handler when executing [`Action::GenerateTableCommitment`]
/// and returned in [`ActionResult::TableCommitmentGenerated`]. The garbler STF
/// accumulates one per circuit and uses them to populate the header fields that
/// the evaluator needs for E8 evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GarblingMetadata {
    /// AES-128 key used by the garbling instance.
    pub aes128_key: [u8; 16],
    /// Public S value used in the CCRND hash function.
    pub public_s: [u8; 16],
    /// Constant wire label for value 0 (wire 0 in the circuit).
    pub constant_zero_label: [u8; 16],
    /// Constant wire label for value 1 (wire 1 in the circuit).
    pub constant_one_label: [u8; 16],
    /// Output label ciphertext — encrypts the output share under the garbler's
    /// output label so the evaluator can recover the share.
    pub output_label_ct: Byte32,
}

/// Identifies an input or output wire
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wire {
    /// Input wire index
    Input(u16),
    /// Output wire
    Output,
}

/// Identifies an input or output wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GeneratedPolynomialCommitments {
    /// Polynomial commitments for all wide label values for an input wire.
    Input {
        /// Input wire index (0..N_INPUT_WIRES).
        wire: u16,
        /// Polynomial commitments for all wide label values for this wire.
        commitments: WideLabelWirePolynomialCommitments,
    },
    /// Polynomial commitment for false value (0) of output wire.
    Output(OutputPolynomialCommitment),
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
