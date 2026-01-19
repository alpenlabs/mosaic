use std::collections::HashMap;

use bitvec::BitArr;
use mosaic_cac_types::{
    AllGarblingTableCommitments, AllPolynomialCommitments, AllPolynomials, ChallengeIndices,
    CompletedSignatures, DepositAdaptors, DepositInput, EvalGarblingSeeds,
    EvalGarblingTableCommitments, InputShares, MsgId, OutputShares, ReservedInputShares, Seed,
    Sighashes, WithdrawalAdaptors, WithdrawalInput,
};
use mosaic_common::constants::N_EVAL_CIRCUITS;

use super::error::GarblerResult;
use crate::garbler::deposit::{DepositId, DepositState};

pub trait GarblerArtifactStore: Sized {
    fn save_polynomials(
        &mut self,
        polynomials: &AllPolynomials,
    ) -> impl Future<Output = GarblerResult<()>>;
    fn load_polynomials(&self) -> impl Future<Output = GarblerResult<Box<AllPolynomials>>>;

    fn save_polynomial_commitments(
        &mut self,
        commitments: &AllPolynomialCommitments,
    ) -> impl Future<Output = GarblerResult<()>>;
    fn load_polynomial_commitments(
        &self,
    ) -> impl Future<Output = GarblerResult<Box<AllPolynomialCommitments>>>;

    fn save_shares(
        &mut self,
        input_shares: &InputShares,
        output_shares: &OutputShares,
    ) -> impl Future<Output = GarblerResult<()>>;
    fn load_shares(
        &self,
    ) -> impl Future<Output = GarblerResult<(Box<InputShares>, Box<OutputShares>)>>;
    fn load_reserved_input_shares(
        &self,
    ) -> impl Future<Output = GarblerResult<Box<ReservedInputShares>>>;

    fn save_garbling_table_commitments(
        &mut self,
        commitments: &AllGarblingTableCommitments,
    ) -> impl Future<Output = GarblerResult<()>>;
    fn load_garbling_table_commitments(
        &self,
    ) -> impl Future<Output = GarblerResult<Box<AllGarblingTableCommitments>>>;

    fn save_challenge_indices(
        &mut self,
        challenge_idxs: &ChallengeIndices,
    ) -> impl Future<Output = GarblerResult<()>>;
    fn load_challenge_indices(&self) -> impl Future<Output = GarblerResult<Box<ChallengeIndices>>>;

    fn save_sighashes_for_deposit(
        &mut self,
        deposit_id: DepositId,
        sighashes: &Sighashes,
    ) -> impl Future<Output = GarblerResult<()>>;
    fn load_sighashes_for_deposit(
        &self,
        deposit_id: DepositId,
    ) -> impl Future<Output = GarblerResult<Box<Sighashes>>>;

    fn save_inputs_for_deposit(
        &mut self,
        deposit_id: DepositId,
        inputs: &DepositInput,
    ) -> impl Future<Output = GarblerResult<()>>;
    fn load_inputs_for_deposit(
        &self,
        deposit_id: DepositId,
    ) -> impl Future<Output = GarblerResult<Box<DepositInput>>>;

    fn save_adaptors_for_deposit(
        &mut self,
        deposit_id: DepositId,
        deposit_adaptors: &DepositAdaptors,
        withdrawal_adaptors: &WithdrawalAdaptors,
    ) -> impl Future<Output = GarblerResult<()>>;
    fn load_adaptors_for_deposit(
        &self,
        deposit_id: DepositId,
    ) -> impl Future<Output = GarblerResult<(Box<DepositAdaptors>, Box<WithdrawalAdaptors>)>>;

    fn save_withdrawal_input(
        &mut self,
        deposit_id: DepositId,
        withdrawal_input: &WithdrawalInput,
    ) -> impl Future<Output = GarblerResult<()>>;
    fn load_withdrawal_input(
        &self,
        deposit_id: DepositId,
    ) -> impl Future<Output = GarblerResult<Box<WithdrawalInput>>>;

    fn save_completed_signatures(
        &mut self,
        deposit_id: DepositId,
        signatures: &CompletedSignatures,
    ) -> impl Future<Output = GarblerResult<()>>;
    fn load_completed_signatures(
        &self,
        deposit_id: DepositId,
    ) -> impl Future<Output = GarblerResult<Box<CompletedSignatures>>>;
}

#[derive(Debug)]
pub struct State<S: GarblerArtifactStore> {
    pub(crate) config: Config,
    pub(crate) context: Context,
    pub(crate) step: Step,
    pub(crate) deposits: HashMap<DepositId, DepositState>,
    pub(crate) artifact_store: S,
}

/// Immutable state that is set during init and never updated
#[derive(Debug)]
pub struct Config {
    pub(crate) seed: Seed,
}

/// Mutable state that is relevant to multiple steps.
/// This should only hold simple bookkeeping related states.
#[derive(Debug, Default)]
pub struct Context {
    /// ID of commit msg that has been sent.
    pub(crate) sent_commit_msg_id: Option<MsgId>,
    /// ID of challenge msg that has been accepted and ACK'd.
    pub(crate) ackd_challenge_msg_id: Option<MsgId>,
    /// ID of challenge response msg that has been sent.
    pub(crate) sent_challenge_response_msg_id: Option<MsgId>,
}

/// Valid states.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[non_exhaustive]
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
    TransferringGarblingTables {
        eval_seeds: Box<EvalGarblingSeeds>,
        eval_commitments: Box<EvalGarblingTableCommitments>,
        transferred: BitArr!(for N_EVAL_CIRCUITS),
    },
    /// Setup is completed, ready to be used for deposits.
    /// Accepts deposit inputs
    SetupComplete,
    /// Disputed Withdrawal is triggered.
    /// Compleing adaptor sigs.
    CompletingAdaptors { deposit_id: DepositId },
    /// Setup is consumed by a withdrawal dispute. Cannot be reused.
    SetupConsumed { deposit_id: DepositId },
    /// Setup was aborted due to a protocol violation.
    Aborted { reason: String },
}
