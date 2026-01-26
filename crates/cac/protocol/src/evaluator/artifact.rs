use mosaic_cac_types::{
    AllGarblingTableCommitments, AllPolynomialCommitments, ChallengeIndices,
    InputPolynomialCommitments, OpenedGarblingSeeds, OpenedInputShares, OpenedOutputShares,
    OutputPolynomialCommitment, ReservedSetupInputShares,
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
}
