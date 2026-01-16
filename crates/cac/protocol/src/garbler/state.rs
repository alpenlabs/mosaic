use std::collections::HashMap;

use mosaic_cac_types::{
    Adaptors, AllPolynomialCommitments, AllPolynomials, AllShares, ChallengeIndices,
    GarblingTableCommitments, MsgId, Seed,
};
use mosaic_common::Byte32;

use crate::garbler::GarblerResult;

pub trait GarblerState: Sized {
    fn save_state(&mut self, s: &State) -> impl Future<Output = GarblerResult<()>>;
    fn load_state(&self) -> impl Future<Output = GarblerResult<State>>;

    fn save_polynomials(
        &mut self,
        polynomials: &AllPolynomials,
    ) -> impl Future<Output = GarblerResult<()>>;
    fn load_polynomials(&mut self) -> impl Future<Output = GarblerResult<Box<AllPolynomials>>>;

    fn save_polynomial_commitments(
        &mut self,
        commitments: &AllPolynomialCommitments,
    ) -> impl Future<Output = GarblerResult<()>>;
    fn load_polynomial_commitments(
        &self,
    ) -> impl Future<Output = GarblerResult<Box<AllPolynomialCommitments>>>;

    fn save_shares(&mut self, shares: &AllShares) -> impl Future<Output = GarblerResult<()>>;
    fn load_shares(&self) -> impl Future<Output = GarblerResult<Box<AllShares>>>;

    fn save_garbling_table_commitments(
        &mut self,
        commitments: &GarblingTableCommitments,
    ) -> impl Future<Output = GarblerResult<()>>;
    fn load_garbling_table_commitments(
        &self,
    ) -> impl Future<Output = GarblerResult<GarblingTableCommitments>>;

    fn save_challenge_indices(
        &mut self,
        challenge_idxs: &ChallengeIndices,
    ) -> impl Future<Output = GarblerResult<()>>;
    fn load_challenge_indices(&self) -> impl Future<Output = GarblerResult<Box<ChallengeIndices>>>;

    fn save_adaptor_for_deposit(
        &mut self,
        deposit_id: DepositId,
        adaptors: Adaptors,
    ) -> impl Future<Output = GarblerResult<()>>;
    fn load_adaptors_for_deposit(
        &self,
        deposit_id: DepositId,
    ) -> impl Future<Output = GarblerResult<Adaptors>>;
}

#[derive(Debug)]
#[expect(dead_code)]
pub struct State {
    pub(crate) config: Config,
    pub(crate) context: Context,
    pub(crate) step: Step,
    pub(crate) deposits: HashMap<DepositId, DepositState>,
}

/// Immutable state that is set during init and never updated
#[derive(Debug)]
pub struct Config {
    pub(crate) seed: Seed,
}

/// Mutable state that is relevant to multiple steps.
/// This should only hold simple bookkeeping related states.
#[derive(Debug, Default)]
#[expect(dead_code)]
pub struct Context {
    /// ID of commit msg that has been sent.
    pub(crate) sent_commit_msg_id: Option<MsgId>,
    /// ID of challenge msg that has been accepted and ACK'd.
    pub(crate) ackd_challenge_msg_id: Option<MsgId>,
    /// ID of challenge response msg that has been sent.
    pub(crate) sent_challenge_response_msg_id: Option<MsgId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepositId(pub Byte32);

#[derive(Debug)]
pub enum DepositState {
    WaitForAdaptors,
    DepositReady,
    WithdrawnUndisputed,
    Consumed,
}

/// Valid states.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[repr(u8)]
pub enum Step {
    #[default]
    Uninit,
    /// Initialized, start generating polynomial commitments
    GeneratingPolynomials,
    /// Polynomials generated.
    /// Generate shares for all tables.
    GeneratingShares,
    /// Dispatch actions to generate commitments.
    /// Wait for all table commitments to be provided.
    GeneratingTableCommitments,
    /// Got table commitments, send commit msg.
    /// Wait for commit msg ack.
    SendingCommit,
    /// Wait for challenge msg
    WaitingForChallenge,
    /// Send challenge response and wait for ack.
    SendingChallengeResponse,
    /// Challenge response msg ack received, send garbling tables
    TransferGarblingTables,
    /// Setup is completed, ready to be used for deposits.
    /// Accepts deposit inputs
    SetupComplete,
    // TODO: withdrawals steps
    /// Setup is consumed by a withdrawal dispute. Cannot be reused.
    SetupConsumed { by_deposit: DepositId },
    /// Setup was aborted due to a protocol violation.
    Aborted { reason: String },
}
