use mosaic_cac_types::{
    AllGarblingTableCommitments, AllPolynomialCommitments, ChallengeIndices,
    ChallengeResponseMsgChunk, CommitMsgChunk, CompletedSignatures, DepositAdaptors, DepositId,
    DepositInputs, InputPolynomialCommitments, OpenedGarblingSeeds, OpenedInputShares,
    OpenedOutputShares, OutputPolynomialCommitment, ReservedSetupInputShares, Sighashes,
    WithdrawalAdaptors, WithdrawalInputs,
};

use crate::SMResult;

pub trait EvaluatorArtifactStore: Sized {
    fn save_polynomial_commitments(
        &mut self,
        commitments: &AllPolynomialCommitments,
    ) -> impl Future<Output = SMResult<()>>;
    fn load_polynomial_commitments(
        &self,
    ) -> impl Future<Output = SMResult<AllPolynomialCommitments>>;
    fn load_input_polynomial_commitments(
        &self,
    ) -> impl Future<Output = SMResult<Box<InputPolynomialCommitments>>>;
    fn load_output_polynomial_commitment(
        &self,
    ) -> impl Future<Output = SMResult<Box<OutputPolynomialCommitment>>>;

    fn save_garbling_table_commitments(
        &mut self,
        commitments: &AllGarblingTableCommitments,
    ) -> impl Future<Output = SMResult<()>>;
    fn load_garbling_table_commitments(
        &self,
    ) -> impl Future<Output = SMResult<Box<AllGarblingTableCommitments>>>;

    fn save_commit_msg_chunk(
        &mut self,
        chunk: CommitMsgChunk,
    ) -> impl Future<Output = SMResult<()>>;

    fn save_challenge_response_msg_chunk(
        &mut self,
        chunk: ChallengeResponseMsgChunk,
    ) -> impl Future<Output = SMResult<()>>;

    fn save_challenge_indices(
        &mut self,
        challenge_idxs: &ChallengeIndices,
    ) -> impl Future<Output = SMResult<()>>;
    fn load_challenge_indices(&self) -> impl Future<Output = SMResult<Box<ChallengeIndices>>>;

    fn save_openend_input_shares(
        &mut self,
        opened_input_shares: &OpenedInputShares,
    ) -> impl Future<Output = SMResult<()>>;
    fn load_openend_input_shares(&self) -> impl Future<Output = SMResult<Box<OpenedInputShares>>>;

    fn save_reserved_setup_input_shares(
        &mut self,
        reserved_setup_input_shares: &ReservedSetupInputShares,
    ) -> impl Future<Output = SMResult<()>>;
    fn load_reserved_setup_input_shares(
        &self,
    ) -> impl Future<Output = SMResult<Box<ReservedSetupInputShares>>>;

    fn save_opened_output_shares(
        &mut self,
        opened_output_shares: &OpenedOutputShares,
    ) -> impl Future<Output = SMResult<()>>;
    fn load_opened_output_shares(&self) -> impl Future<Output = SMResult<Box<OpenedOutputShares>>>;

    fn save_opened_garbling_seeds(
        &mut self,
        opened_garbling_seeds: &OpenedGarblingSeeds,
    ) -> impl Future<Output = SMResult<()>>;
    fn load_opened_garbling_seeds(
        &self,
    ) -> impl Future<Output = SMResult<Box<OpenedGarblingSeeds>>>;

    fn save_sighashes_for_deposit(
        &mut self,
        deposit_id: DepositId,
        sighashes: &Sighashes,
    ) -> impl Future<Output = SMResult<()>>;
    fn load_sighashes_for_deposit(
        &self,
        deposit_id: DepositId,
    ) -> impl Future<Output = SMResult<Box<Sighashes>>>;

    fn save_inputs_for_deposit(
        &mut self,
        deposit_id: DepositId,
        inputs: &DepositInputs,
    ) -> impl Future<Output = SMResult<()>>;
    fn load_inputs_for_deposit(
        &self,
        deposit_id: DepositId,
    ) -> impl Future<Output = SMResult<Box<DepositInputs>>>;

    fn save_adaptors_for_deposit(
        &mut self,
        deposit_id: DepositId,
        deposit_adaptors: &DepositAdaptors,
        withdrawal_adaptors: &WithdrawalAdaptors,
    ) -> impl Future<Output = SMResult<()>>;
    fn load_adaptors_for_deposit(
        &self,
        deposit_id: DepositId,
    ) -> impl Future<Output = SMResult<(Box<DepositAdaptors>, Box<WithdrawalAdaptors>)>>;

    fn save_withdrawal_inputs(
        &mut self,
        deposit_id: DepositId,
        withdrawal_input: &WithdrawalInputs,
    ) -> impl Future<Output = SMResult<()>>;
    fn load_withdrawal_inputs(
        &self,
        deposit_id: DepositId,
    ) -> impl Future<Output = SMResult<Box<WithdrawalInputs>>>;

    fn save_completed_signatures(
        &mut self,
        deposit_id: DepositId,
        signatures: &CompletedSignatures,
    ) -> impl Future<Output = SMResult<()>>;
    fn load_completed_signatures(
        &self,
        deposit_id: DepositId,
    ) -> impl Future<Output = SMResult<Box<CompletedSignatures>>>;
}
