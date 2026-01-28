use fasm::actions::TrackedActionTypes;
use mosaic_vs3::Index;

#[allow(unused_imports, reason = "docs")]
use crate::state_machine::{evaluator, garbler};
use crate::{
    ChallengeResponseMsg, CommitMsg, DepositAdaptors, DepositId, GarblingSeed, InputShares, MsgId,
    PubKey, ReservedDepositInputShares, ReservedWithdrawalInputShares, Sighashes,
    WithdrawalAdaptors, WithdrawalInputs,
};

/// Actions emitted by the garbler state machine for external execution.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Action {
    /// Generate polynomials from the base seed.
    /// Result: [`garbler::Input::PolynomialCommitmentsGenerated`]
    GeneratePolynomialCommitments,
    /// Generate input/output shares from polynomials.
    /// Result: [`garbler::Input::SharesGenerated`]
    GenerateShares(Index),
    /// Result: [`garbler::Input::TableCommitmentGenerated`]
    /// Generate single table's garbling table commitment from seeds and shares.
    GenerateTableCommitment(Index, GarblingSeed),
    /// Send commit message with polynomial and table commitments to evaluator.
    /// Result: [`evaluator::Input::RecvCommitMsg`] on evaluator
    SendCommitMsg(CommitMsg),
    /// Acknowledge receipt of challenge message from evaluator.
    /// Result: [`evaluator::Input::ChallengeMsgAcked`] on evaluator
    AckChallengeMsg(MsgId),
    /// Send challenge response with revealed seeds and shares.
    /// Result: [`evaluator::Input::RecvChallengeResponseMsg`] on evaluator
    SendChallengeResponseMsg(ChallengeResponseMsg),
    /// Transfer a garbling table to the evaluator.
    /// Result: [`garbler::Input::GarblingTableTransferred`]
    TransferGarblingTable(GarblingSeed),

    /// Acknowledge receipt of adaptor signatures for a deposit.
    /// Result: [`evaluator::Input::DepositAdaptorMsgAcked`] on evaluator
    DepositAckAdaptorMsg(DepositId, MsgId),
    /// Verify adaptor signatures received from evaluator.
    /// Result: [`garbler::Input::DepositAdaptorVerificationResult`]
    DepositVerifyAdaptors(DepositId, AdaptorVerificationData),

    /// Complete adaptor signatures for a disputed withdrawal.
    /// Result: [`garbler::Input::AdaptorSignaturesCompleted`]
    CompleteAdaptorSignatures(DepositId, CompleteAdaptorSignaturesData),
}

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

/// Placeholder for untracked actions (currently unused).
#[derive(Debug)]
pub enum UntrackedAction {}

/// Type marker for garbler tracked action types.
#[derive(Debug)]
pub struct GarblerTrackedActionTypes;

impl TrackedActionTypes for GarblerTrackedActionTypes {
    type Id = ();

    type Action = Action;

    type Result = ();
}

/// Container for garbler actions.
pub type ActionContainer = Vec<fasm::actions::Action<UntrackedAction, GarblerTrackedActionTypes>>;
