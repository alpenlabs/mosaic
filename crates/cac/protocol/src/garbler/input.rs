use mosaic_cac_types::{
    AdaptorMsg, AllGarblingTableCommitments, AllPolynomialCommitments, AllPolynomials,
    ChallengeMsg, CompletedSignatures, DepositId, DepositInput, GarblingSeed,
    GarblingTableCommitment, InputShares, MsgId, OutputShares, PubKey, Sighashes, WithdrawalInput,
};

use super::state::Config;

#[derive(Debug)]
#[non_exhaustive]
pub enum Input {
    Init(Config),
    PolynomialsGenerated(Box<AllPolynomials>, Box<AllPolynomialCommitments>),
    SharesGenerated(Box<InputShares>, Box<OutputShares>),
    TableCommitmentsGenerated(Box<AllGarblingTableCommitments>),
    CommitMsgAcked(MsgId),
    RecvChallengeMsg(ChallengeMsg),
    ChallengeResponseAcked(MsgId),
    GarblingTableTransferred(GarblingSeed, GarblingTableCommitment),

    DepositInit(DepositId, DepositInitData),
    DepositRecvAdaptorMsg(DepositId, AdaptorMsg),
    DepositAdaptorVerificationResult(DepositId, bool),
    DepositUndisputedWithdrawal(DepositId),

    DisputedWithdrawal(DepositId, Box<WithdrawalInput>),
    AdaptorSignaturesCompleted(DepositId, Box<CompletedSignatures>),
}

#[derive(Debug)]
pub struct DepositInitData {
    pub pk: PubKey,
    pub sighashes: Box<Sighashes>,
    pub deposit_input: Box<DepositInput>,
}
