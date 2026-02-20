use std::{error::Error, fmt::Debug};

use futures::Stream;

use super::{DepositState, GarblerState};
use crate::{
    AdaptorMsgChunk, AllGarblingTableCommitments, ChallengeIndices, CircuitInputShares,
    CircuitOutputShare, CompletedSignatures, DepositAdaptors, DepositId, DepositInputs,
    GarblingTableCommitment, Index, InputPolynomialCommitments, InputShares,
    OutputPolynomialCommitment, OutputShares, ReservedInputShares, Sighashes,
    WideLabelWirePolynomialCommitments, WithdrawalAdaptors, WithdrawalInputs,
};

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

    fn get_input_polynomial_commitments(
        &self,
    ) -> impl Future<Output = Result<Option<InputPolynomialCommitments>, Self::Error>> + Send;

    fn get_output_polynomial_commitment(
        &self,
    ) -> impl Future<Output = Result<Option<OutputPolynomialCommitment>, Self::Error>> + Send;

    fn get_input_shares(
        &self,
    ) -> impl Future<Output = Result<Option<InputShares>, Self::Error>> + Send;

    fn get_output_shares(
        &self,
    ) -> impl Future<Output = Result<Option<OutputShares>, Self::Error>> + Send;

    fn get_reserved_input_shares(
        &self,
    ) -> impl Future<Output = Result<Option<ReservedInputShares>, Self::Error>> + Send;

    fn get_garbling_table_commitment(
        &self,
        index: Index,
    ) -> impl Future<Output = Result<Option<GarblingTableCommitment>, Self::Error>> + Send;

    fn get_all_garbling_table_commitments(
        &self,
    ) -> impl Future<Output = Result<Option<AllGarblingTableCommitments>, Self::Error>> + Send;

    fn get_challenge_indices(
        &self,
    ) -> impl Future<Output = Result<Option<ChallengeIndices>, Self::Error>> + Send;

    fn get_deposit_sighashes(
        &self,
        deposit_id: &DepositId,
    ) -> impl Future<Output = Result<Option<Sighashes>, Self::Error>> + Send;

    fn get_deposit_inputs(
        &self,
        deposit_id: &DepositId,
    ) -> impl Future<Output = Result<Option<DepositInputs>, Self::Error>> + Send;

    fn get_withdrawal_input(
        &self,
        deposit_id: &DepositId,
    ) -> impl Future<Output = Result<Option<WithdrawalInputs>, Self::Error>> + Send;

    fn get_deposit_adaptors(
        &self,
        deposit_id: &DepositId,
    ) -> impl Future<Output = Result<Option<DepositAdaptors>, Self::Error>> + Send;

    fn get_withdrawal_adaptors(
        &self,
        deposit_id: &DepositId,
    ) -> impl Future<Output = Result<Option<WithdrawalAdaptors>, Self::Error>> + Send;

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
