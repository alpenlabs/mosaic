use std::{error::Error, fmt::Debug};

use futures::Stream;
use mosaic_cac_types::{
    AllGarblingTableCommitments, ChallengeIndices, CircuitInputShares, CompletedSignatures,
    DepositAdaptors, DepositId, DepositInputs, InputPolynomialCommitments, OpenedGarblingSeeds,
    OpenedInputShares, OpenedOutputShares, OutputPolynomialCommitment, ReservedSetupInputShares,
    Sighashes, WideLabelWirePolynomialCommitments, WithdrawalAdaptors, WithdrawalInputs,
};

use crate::evaluator::{deposit::DepositState, root_state::EvaluatorState};

pub trait StateRead {
    type Error: Error + Debug + 'static;

    fn get_root_state(
        &self,
    ) -> impl Future<Output = Result<Option<EvaluatorState>, Self::Error>> + Send;

    fn get_deposit(
        &self,
        deposit_id: &DepositId,
    ) -> impl Future<Output = Result<Option<DepositState>, Self::Error>> + Send;

    fn stream_all_deposits(
        &self,
    ) -> impl Stream<Item = Result<(DepositId, DepositState), Self::Error>> + Send;

    fn get_input_polynomial_commitments(
        &self,
    ) -> impl Future<Output = Result<InputPolynomialCommitments, Self::Error>> + Send;

    fn get_output_polynomial_commitment(
        &self,
    ) -> impl Future<Output = Result<OutputPolynomialCommitment, Self::Error>> + Send;

    fn get_garbling_table_commitments(
        &self,
    ) -> impl Future<Output = Result<AllGarblingTableCommitments, Self::Error>> + Send;

    fn get_challenge_indices(
        &self,
    ) -> impl Future<Output = Result<ChallengeIndices, Self::Error>> + Send;

    fn get_opened_input_shares(
        &self,
    ) -> impl Future<Output = Result<Box<OpenedInputShares>, Self::Error>> + Send;

    fn get_reserved_setup_input_shares(
        &self,
    ) -> impl Future<Output = Result<ReservedSetupInputShares, Self::Error>> + Send;

    fn get_opened_output_shares(
        &self,
    ) -> impl Future<Output = Result<OpenedOutputShares, Self::Error>> + Send;

    fn get_opened_garbling_seeds(
        &self,
    ) -> impl Future<Output = Result<OpenedGarblingSeeds, Self::Error>> + Send;

    fn get_sighashes_for_deposit(
        &self,
        deposit_id: &DepositId,
    ) -> impl Future<Output = Result<Box<Sighashes>, Self::Error>> + Send;

    fn get_inputs_for_deposit(
        &self,
        deposit_id: &DepositId,
    ) -> impl Future<Output = Result<DepositInputs, Self::Error>> + Send;

    fn get_adaptors_for_deposit(
        &self,
        deposit_id: &DepositId,
    ) -> impl Future<Output = Result<(DepositAdaptors, WithdrawalAdaptors), Self::Error>> + Send;

    fn get_withdrawal_inputs(
        &self,
        deposit_id: &DepositId,
    ) -> impl Future<Output = Result<Box<WithdrawalInputs>, Self::Error>> + Send;

    fn get_completed_signatures(
        &self,
        deposit_id: &DepositId,
    ) -> impl Future<Output = Result<Box<CompletedSignatures>, Self::Error>> + Send;
}

pub trait StateMut: StateRead {
    fn put_root_state(
        &mut self,
        state: &EvaluatorState,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    fn put_deposit(
        &mut self,
        deposit_id: &DepositId,
        deposit_state: &DepositState,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    fn put_input_polynomial_commitments_chunk(
        &mut self,
        wire_idx: u16,
        commitments: &WideLabelWirePolynomialCommitments,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    fn put_output_polynomial_commitment(
        &mut self,
        commitment: &OutputPolynomialCommitment,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    fn put_garbling_table_commitments(
        &mut self,
        commitments: &AllGarblingTableCommitments,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    fn put_challenge_indices(
        &mut self,
        challenge_idxs: &ChallengeIndices,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Save input shares for opened circuits, one chunk per circuit.
    fn put_opened_input_shares_chunk(
        &mut self,
        opened_ckt_idx: u16,
        input_shares: &CircuitInputShares,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    fn put_reserved_setup_input_shares(
        &mut self,
        reserved_setup_input_shares: &ReservedSetupInputShares,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    fn put_opened_output_shares(
        &mut self,
        opened_output_shares: &OpenedOutputShares,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    fn put_opened_garbling_seeds(
        &mut self,
        opened_garbling_seeds: &OpenedGarblingSeeds,
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

    fn put_adaptors_for_deposit(
        &mut self,
        deposit_id: &DepositId,
        deposit_adaptors: &DepositAdaptors,
        withdrawal_adaptors: &WithdrawalAdaptors,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    fn put_withdrawal_inputs(
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
