use mosaic_cac_types::{
    AllGarblingTableCommitments, AllPolynomialCommitments, AllPolynomials, ChallengeIndices,
    CompletedSignatures, DepositAdaptors, DepositId, DepositInputs, InputShares, OutputShares,
    ReservedInputShares, Sighashes, WithdrawalAdaptors, WithdrawalInputs,
};

use crate::SMResult;

pub trait GarblerArtifactStore: Sized {
    fn save_polynomials(
        &mut self,
        polynomials: &AllPolynomials,
    ) -> impl Future<Output = SMResult<()>>;
    fn load_polynomials(&self) -> impl Future<Output = SMResult<AllPolynomials>>;

    fn save_polynomial_commitments(
        &mut self,
        commitments: &AllPolynomialCommitments,
    ) -> impl Future<Output = SMResult<()>>;
    fn load_polynomial_commitments(
        &self,
    ) -> impl Future<Output = SMResult<AllPolynomialCommitments>>;

    fn save_shares(
        &mut self,
        input_shares: &InputShares,
        output_shares: &OutputShares,
    ) -> impl Future<Output = SMResult<()>>;
    fn load_shares(&self) -> impl Future<Output = SMResult<(Box<InputShares>, Box<OutputShares>)>>;
    fn load_reserved_input_shares(
        &self,
    ) -> impl Future<Output = SMResult<Box<ReservedInputShares>>>;

    fn save_garbling_table_commitments(
        &mut self,
        commitments: &AllGarblingTableCommitments,
    ) -> impl Future<Output = SMResult<()>>;
    fn load_garbling_table_commitments(
        &self,
    ) -> impl Future<Output = SMResult<Box<AllGarblingTableCommitments>>>;

    fn save_challenge_indices(
        &mut self,
        challenge_idxs: &ChallengeIndices,
    ) -> impl Future<Output = SMResult<()>>;
    fn load_challenge_indices(&self) -> impl Future<Output = SMResult<Box<ChallengeIndices>>>;

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

    fn save_withdrawal_input(
        &mut self,
        deposit_id: DepositId,
        withdrawal_input: &WithdrawalInputs,
    ) -> impl Future<Output = SMResult<()>>;
    fn load_withdrawal_input(
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
