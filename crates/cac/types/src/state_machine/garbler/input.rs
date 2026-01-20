use crate::{
    AdaptorMsg, AllGarblingTableCommitments, AllPolynomialCommitments, AllPolynomials,
    ChallengeMsg, CompletedSignatures, DepositId, DepositInputs, GarblingSeed,
    GarblingTableCommitment, InputShares, MsgId, OutputShares, PubKey, Seed, SetupInputs,
    Sighashes, WithdrawalInputs,
};

/// Garbler state machine inputs.
#[derive(Debug)]
#[non_exhaustive]
pub enum Input {
    /// Initialize garbler state machine.
    Init(GarblerInitData),
    /// Polynomials and polynomial commitments generated.
    PolynomialsGenerated(Box<AllPolynomials>, Box<AllPolynomialCommitments>),
    /// Input and output wire shares generated.
    SharesGenerated(Box<InputShares>, Box<OutputShares>),
    /// Garbling table commitments generated.
    TableCommitmentsGenerated(Box<AllGarblingTableCommitments>),
    /// Commit message with specified `MsgId` was acked.
    CommitMsgAcked(MsgId),
    /// Challenge message received.
    RecvChallengeMsg(ChallengeMsg),
    /// Challenge response message with specified `MsgId` was acked.
    ChallengeResponseAcked(MsgId),
    /// Garbling table generated with specified seed was transferred to the other party.
    GarblingTableTransferred(GarblingSeed, GarblingTableCommitment),

    /// Initialize deposit for specified deposit id.
    DepositInit(DepositId, GarblerDepositInitData),
    /// Adaptor message received for this deposit.
    DepositRecvAdaptorMsg(DepositId, AdaptorMsg),
    /// Deposit adaptor verification passed or failed.
    DepositAdaptorVerificationResult(DepositId, bool),
    /// Mark deposit as withdrawn without dispute.
    DepositUndisputedWithdrawal(DepositId),
    /// Initiate disputed withdrawal for this deposit.
    DisputedWithdrawal(DepositId, Box<WithdrawalInputs>),
    /// Adaptor signatures completed for this deposit.
    AdaptorSignaturesCompleted(DepositId, Box<CompletedSignatures>),
}

/// Data required during garbler state machine setup.
#[derive(Debug)]
pub struct GarblerInitData {
    /// Seed for deterministic rng.
    pub seed: Seed,
    /// Setup input wire values.
    pub setup_inputs: SetupInputs,
}

/// Data required to create a deposit.
#[derive(Debug)]
pub struct GarblerDepositInitData {
    /// Public key used to verify adaptors created under evaluator's secret key.
    pub pk: PubKey,
    /// Sighashes to be signed using the adaptors.
    pub sighashes: Box<Sighashes>,
    /// Deposit input wire values.
    pub deposit_inputs: Box<DepositInputs>,
}
