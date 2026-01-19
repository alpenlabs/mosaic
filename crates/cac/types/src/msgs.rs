use std::fmt::Display;

use crate::{
    AllGarblingTableCommitments, AllPolynomialCommitments, ChallengeIndices, DepositAdaptors,
    OpenedGarblingSeeds, OpenedInputShares, OpenedOutputShares, ReservedSetupInputShares,
    WithdrawalAdaptors,
};
/// CommitMsg: Garbler -> Evaluator
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitMsg {
    /// N_INPUT_WIRES * 256 + 1
    pub polynomial_commitments: Box<AllPolynomialCommitments>,
    /// N_CIRCUITS
    pub garbling_table_commitments: Box<AllGarblingTableCommitments>,
}

/// ChallengeMsg: Evaluator -> Garbler
#[derive(Clone, Debug)]
pub struct ChallengeMsg {
    /// N_COEFFICIENTS
    pub challenge_indices: Box<ChallengeIndices>,
}

/// ChallengeResponseMsg: Garbler -> Evaluator
/// Note: Garbling Tables are sent separately
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChallengeResponseMsg {
    /// N_COEFFICIENTS * N_INPUT_WIRES * 256
    pub opened_input_shares: Box<OpenedInputShares>,
    /// N_SETUP_INPUT_WIRES * 256
    pub reserved_setup_input_shares: Box<ReservedSetupInputShares>,
    /// N_COEFFICIENTS
    pub opened_output_shares: Box<OpenedOutputShares>,
    /// N_COEFFICIENTS
    pub opened_garbling_seeds: Box<OpenedGarblingSeeds>,
}

/// AdaptorMsg: Evaluator -> Garbler
#[derive(Clone, Debug)]
pub struct AdaptorMsg {
    /// N_DEPOSIT_INPUT_WIRES
    pub deposit_adaptors: Box<DepositAdaptors>,
    /// N_WITHDRAWAL_INPUT_WIRES * 256
    pub withdrawal_adaptors: Box<WithdrawalAdaptors>,
}

/// Unique identifier for a message passed between garbler and evaluator nodes.
/// Used for deduplication and ACKs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MsgId(pub [u8; 32]);

impl Display for MsgId {
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

/// Provide MsgId from specific msg types.
pub trait HasMsgId {
    /// get MsgId.
    fn id(&self) -> MsgId;
}

impl HasMsgId for CommitMsg {
    fn id(&self) -> MsgId {
        todo!()
    }
}
impl HasMsgId for ChallengeMsg {
    fn id(&self) -> MsgId {
        todo!()
    }
}
impl HasMsgId for ChallengeResponseMsg {
    fn id(&self) -> MsgId {
        todo!()
    }
}
impl HasMsgId for AdaptorMsg {
    fn id(&self) -> MsgId {
        todo!()
    }
}

/// All Valid message types between peers
#[allow(missing_docs, reason = "wip")]
#[derive(Debug)]
pub enum Msg {
    CommitMsg(CommitMsg),
    ChallengeMsg(ChallengeMsg),
    ChallengeResponseMsg(ChallengeResponseMsg),
    AdaptorMsg(AdaptorMsg),
    CommitMsgAck(MsgId),
    ChallengeMsgAck(MsgId),
    ChallengeResponseMsgAck(MsgId),
    AdaptorMsgAck(MsgId),
}
