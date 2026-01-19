use mosaic_cac_types::{
    AllGarblingSeeds, AllPolynomials, ChallengeResponseMsg, CommitMsg, DepositAdaptors,
    GarblingSeed, GarblingTableCommitment, InputShares, MsgId, OutputShares, PubKey,
    ReservedDepositInputShares, ReservedWithdrawalInputShares, Seed, Sighashes, WithdrawalAdaptors,
    WithdrawalInput,
};

use super::deposit::DepositId;

#[derive(Debug, PartialEq, Eq)]
pub struct TableTransferRequest {
    pub seed: Seed,
    pub commitment: GarblingTableCommitment,
}

#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Action {
    GeneratePolynomials(Seed),
    GenerateShares(Box<AllPolynomials>),
    GenerateTableCommitments(Box<AllGarblingSeeds>, Box<InputShares>, Box<OutputShares>),
    SendCommitMsg(CommitMsg),
    AckChallengeMsg(MsgId),
    SendChallengeResponseMsg(ChallengeResponseMsg),
    TransferGarblingTable(GarblingSeed),

    DepositAckAdaptorMsg(DepositId, MsgId),
    DepositVerifyAdaptors(DepositId, AdaptorVerificationData),

    CompleteAdaptorSignatures(DepositId, CompleteAdaptorSignaturesData),
}

#[derive(Debug, PartialEq, Eq)]
pub struct AdaptorVerificationData {
    pub pk: PubKey,
    pub deposit_adaptors: Box<DepositAdaptors>,
    pub withdrawal_adaptors: Box<WithdrawalAdaptors>,
    pub input_shares: Box<InputShares>,
    pub sighashes: Box<Sighashes>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct CompleteAdaptorSignaturesData {
    pub pk: PubKey,
    pub sighashes: Box<Sighashes>,
    pub deposit_adaptors: Box<DepositAdaptors>,
    pub withdrawal_adaptors: Box<WithdrawalAdaptors>,
    pub deposit_input_shares: Box<ReservedDepositInputShares>,
    pub withdrawal_input_shares: Box<ReservedWithdrawalInputShares>,
    pub withdrawal_input: Box<WithdrawalInput>,
}
