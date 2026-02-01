use mosaic_vs3::Index;

use crate::{
    ChallengeResponseMsgChunk, CircuitOutputShare, CommitMsgChunk, CompletedSignatures,
    DepositAdaptors, DepositId, DepositInputs, GarblingTableCommitment, SecretKey, Seed,
    SetupInputs, Sighashes, WithdrawalAdaptors, WithdrawalInputs,
};

/// Evaluator state machine inputs.
#[derive(Debug)]
#[non_exhaustive]
pub enum Input {
    /// Initialize evaluator state machine.
    Init(EvaluatorInitData),
    /// Commit message chunk received.
    RecvCommitMsgChunk(CommitMsgChunk),
    /// Challenge message was acked by peer.
    ChallengeMsgAcked,
    /// Challenge response message chunk received.
    RecvChallengeResponseMsgChunk(ChallengeResponseMsgChunk),
    /// Opened input shares verification failure message or None.
    VerifyOpenedInputSharesResult(Option<String>),
    /// Garbling table commitment generated.
    TableCommitmentGenerated(Index, GarblingTableCommitment),
    /// Garbling table received from garbler.
    GarblingTableReceived(Index, GarblingTableCommitment),
    /// Initialize deposit for specified deposit id.
    DepositInit(DepositId, EvaluatorDepositInitData),
    /// Adaptors generated for deposit and withdrawal wires.
    DepositAdaptorsGenerated(DepositId, Box<DepositAdaptors>, Box<WithdrawalAdaptors>),
    /// Adaptor message was acked by peer for this deposit.
    DepositAdaptorMsgAcked(DepositId),
    /// Mark deposit as withdrawn without dispute.
    DepositUndisputedWithdrawal(DepositId),
    /// Initiate disputed withdrawal for this deposit.
    DisputedWithdrawal(DepositId, EvaluatorDisputedWithdrawalData),
    /// Result of a garbling table evaluation.
    TableEvaluationResult(GarblingTableCommitment, Option<CircuitOutputShare>),
}

/// Data required during evaluator state machine setup.
#[derive(Debug)]
pub struct EvaluatorInitData {
    /// Seed for deterministic rng.
    pub seed: Seed,
    /// Setup input wire values.
    pub setup_inputs: SetupInputs,
}

/// Data required to create a deposit.
#[derive(Debug)]
pub struct EvaluatorDepositInitData {
    /// Secret key used to generate adaptors.
    pub sk: SecretKey,
    /// Sighashes to be signed using the adaptors.
    pub sighashes: Box<Sighashes>,
    /// Deposit input wire values.
    pub deposit_inputs: Box<DepositInputs>,
}

/// Data required to initiate disputed withdrawal process.
#[derive(Debug)]
pub struct EvaluatorDisputedWithdrawalData {
    /// Withdrawal input wire values.
    // NOTE: this might not be required
    pub withdrawal_inputs: Box<WithdrawalInputs>,
    /// Completed adaptor signatures extracted from on chain transaction.
    pub signatures: Box<CompletedSignatures>,
}
