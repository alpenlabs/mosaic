use std::fmt::Display;

use mosaic_common::constants::{
    N_DEPOSIT_INPUT_WIRES, N_INPUT_WIRES, N_SETUP_INPUT_WIRES, N_WITHDRAWAL_INPUT_WIRES,
};
use mosaic_vs3::{Index, N_CIRCUITS, N_COEFFICIENTS, PolynomialCommitment, Share};

use crate::{Adaptor, GarblingTableCommitment, Seed};

/// Setup input values, represents bridge operator pubky
pub type SetupInputs = [u8; N_SETUP_INPUT_WIRES];

/// N_INPUT_WIRES * 256 + 1
pub type PolynomialCommitments = [[PolynomialCommitment; 256 + 1]; N_INPUT_WIRES];
/// N_CIRCUITS
pub type GarblingTableCommitments = [GarblingTableCommitment; N_CIRCUITS];
/// N_COEFFICIENTS
pub type ChallengeIndices = [Index; N_COEFFICIENTS];
/// N_COEFFICIENTS * N_INPUT_WIRES * 256
pub type OpenedInputShares = [[[Share; 256]; N_INPUT_WIRES]; N_COEFFICIENTS];
/// N_SETUP_INPUT_WIRES * 256
pub type ReservedSetupInputShares = [[Share; 256]; N_SETUP_INPUT_WIRES];
/// N_COEFFICIENTS
pub type OpenedOutputShares = [Share; N_COEFFICIENTS];
/// N_COEFFICIENTS
pub type OpenedGarblingSeeds = [Seed; N_COEFFICIENTS];

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

/// CommitMsg: Garbler -> Evaluator
#[derive(Clone, Debug)]
pub struct CommitMsg {
    /// N_INPUT_WIRES * 256 + 1
    pub polynomial_commitments: PolynomialCommitments,
    /// N_CIRCUITS
    pub garbling_table_commitments: GarblingTableCommitments,
}

/// ChallengeMsg: Evaluator -> Garbler
#[derive(Clone, Debug)]
pub struct ChallengeMsg {
    /// N_COEFFICIENTS
    pub challenge_indices: ChallengeIndices,
}

/// ChallengeResponseMsg: Garbler -> Evaluator
/// Note: Garbling Tables are sent separately
#[derive(Clone, Debug)]
pub struct ChallengeResponseMsg {
    /// N_COEFFICIENTS * N_INPUT_WIRES * 256
    pub opened_input_shares: OpenedInputShares,
    /// N_SETUP_INPUT_WIRES * 256
    pub reserved_setup_input_shares: ReservedSetupInputShares,
    /// N_COEFFICIENTS
    pub opened_output_shares: OpenedOutputShares,
    /// N_COEFFICIENTS
    pub opened_garbling_seeds: OpenedGarblingSeeds,
}

/// AdaptorMsg: Evaluator -> Garbler
#[derive(Clone, Debug)]
pub struct AdaptorMsg {
    /// N_DEPOSIT_INPUT_WIRES
    pub deposit_adaptors: [Adaptor; N_DEPOSIT_INPUT_WIRES],
    /// N_WITHDRAWAL_INPUT_WIRES * 256
    pub withdrawal_adaptors: [[Adaptor; 256]; N_WITHDRAWAL_INPUT_WIRES],
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
