use std::{error::Error, fmt::Debug};

use futures::Stream;
use mosaic_cac_types::{
    AdaptorMsgChunk, AllGarblingTableCommitments, AllPolynomialCommitments, AllPolynomials,
    ChallengeIndices, CircuitInputShares, CircuitOutputShare, CompletedSignatures, DepositAdaptors,
    DepositId, DepositInputs, GarblingTableCommitment, Index, InputShares,
    OutputPolynomialCommitment, OutputShares, ReservedInputShares, Sighashes,
    WideLabelWirePolynomialCommitments, WithdrawalAdaptors, WithdrawalInputs,
};

use crate::garbler::{deposit::DepositState, root_state::GarblerState};

pub trait StateRead {
    type Error: Error + Debug + 'static;

    fn get_root_state(
        &self,
    ) -> impl Future<Output = Result<Option<GarblerState>, Self::Error>> + Send;

    fn get_deposit(
        &self,
        deposit_id: &DepositId,
    ) -> impl Future<Output = Result<Option<DepositState>, Self::Error>> + Send;

    fn stream_all_deposits(
        &self,
    ) -> impl Stream<Item = Result<(DepositId, DepositState), Self::Error>> + Send;

    fn get_polynomials(&self) -> impl Future<Output = Result<AllPolynomials, Self::Error>> + Send;

    fn get_polynomial_commitments(
        &self,
    ) -> impl Future<Output = Result<AllPolynomialCommitments, Self::Error>> + Send;

    fn get_shares(
        &self,
    ) -> impl Future<Output = Result<(InputShares, OutputShares), Self::Error>> + Send;

    fn get_reserved_input_shares(
        &self,
    ) -> impl Future<Output = Result<ReservedInputShares, Self::Error>> + Send;

    fn get_garbling_table_commitment(
        &self,
        index: Index,
    ) -> impl Future<Output = Result<Option<GarblingTableCommitment>, Self::Error>> + Send;

    fn get_all_garbling_table_commitments(
        &self,
    ) -> impl Future<Output = Result<AllGarblingTableCommitments, Self::Error>> + Send;

    fn get_challenge_indices(
        &self,
    ) -> impl Future<Output = Result<ChallengeIndices, Self::Error>> + Send;

    fn get_sighashes_for_deposit(
        &self,
        deposit_id: &DepositId,
    ) -> impl Future<Output = Result<Sighashes, Self::Error>> + Send;

    fn get_inputs_for_deposit(
        &self,
        deposit_id: &DepositId,
    ) -> impl Future<Output = Result<DepositInputs, Self::Error>> + Send;

    fn get_adaptors_for_deposit(
        &self,
        deposit_id: &DepositId,
    ) -> impl Future<Output = Result<(DepositAdaptors, WithdrawalAdaptors), Self::Error>> + Send;

    fn get_withdrawal_input(
        &self,
        deposit_id: &DepositId,
    ) -> impl Future<Output = Result<WithdrawalInputs, Self::Error>> + Send;

    fn get_completed_signatures(
        &self,
        deposit_id: &DepositId,
    ) -> impl Future<Output = Result<CompletedSignatures, Self::Error>> + Send;
}

pub trait StateMut: StateRead {
    fn put_root_state(
        &mut self,
        state: &GarblerState,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    fn put_deposit(
        &mut self,
        deposit_id: DepositId,
        deposit_state: &DepositState,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    fn put_polynomials(
        &mut self,
        polynomials: &AllPolynomials,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Save polynomial commitments for one input wire (~ 5KB * 256 = 4.2MB approx)
    fn put_input_polynomial_commitments_chunk(
        &mut self,
        wire_idx: u16,
        commitments: &WideLabelWirePolynomialCommitments,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Save output polynomial commitment (~5KB)
    fn put_output_polynomial_commitment(
        &mut self,
        commitments: &OutputPolynomialCommitment,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    fn put_shares_for_index(
        &mut self,
        index: Index,
        input_shares: &CircuitInputShares,
        output_share: &CircuitOutputShare,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    fn put_garbling_table_commitment(
        &mut self,
        index: Index,
        commitments: &GarblingTableCommitment,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    fn put_challenge_indices(
        &mut self,
        challenge_idxs: &ChallengeIndices,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    fn put_sighashes_for_deposit(
        &mut self,
        deposit_id: &DepositId,
        sighashes: &Sighashes,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    fn put_inputs_for_deposit(
        &mut self,
        deposit_id: &DepositId,
        inputs: &DepositInputs,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    fn put_adaptor_msg_chunk_for_deposit(
        &mut self,
        deposit_id: &DepositId,
        adaptor_chunk: &AdaptorMsgChunk,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    fn put_withdrawal_input(
        &mut self,
        deposit_id: &DepositId,
        withdrawal_input: &WithdrawalInputs,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    fn put_completed_signatures(
        &mut self,
        deposit_id: &DepositId,
        signatures: &CompletedSignatures,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}
