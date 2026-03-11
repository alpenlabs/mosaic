use std::{error::Error, fmt::Debug};

use futures::Stream;
use mosaic_common::Byte32;
use mosaic_vs3::Index;

use super::{DepositState, EvaluatorState};
use crate::{
    AllGarblingTableCommitments, ChallengeIndices, CircuitInputShares, CompletedSignatures,
    DepositAdaptors, DepositId, DepositInputs, EvaluationIndices, InputPolynomialCommitments,
    OpenedGarblingSeeds, OpenedInputShares, OpenedOutputShares, OutputPolynomialCommitment,
    ReservedSetupInputShares, Sighashes, WideLabelWirePolynomialCommitments, WithdrawalAdaptors,
    WithdrawalAdaptorsChunk, WithdrawalInputs,
};

/// Read-only access to evaluator state storage.
pub trait StateRead {
    /// Error type used by state operations.
    type Error: Error + Debug + 'static;

    /// Retrieves the root evaluator state.
    fn get_root_state(
        &self,
    ) -> impl Future<Output = Result<Option<EvaluatorState>, Self::Error>> + Send;

    /// Retrieves the state for a specific deposit.
    fn get_deposit(
        &self,
        deposit_id: &DepositId,
    ) -> impl Future<Output = Result<Option<DepositState>, Self::Error>> + Send;

    /// Streams all deposits with their IDs and states.
    fn stream_all_deposits(
        &self,
    ) -> impl Stream<Item = Result<(DepositId, DepositState), Self::Error>> + Send;

    /// Retrieves commitments to input polynomials.
    fn get_input_polynomial_commitments(
        &self,
    ) -> impl Future<Output = Result<Option<InputPolynomialCommitments>, Self::Error>> + Send;

    /// Retrieves the commitment to output polynomial.
    fn get_output_polynomial_commitment(
        &self,
    ) -> impl Future<Output = Result<Option<OutputPolynomialCommitment>, Self::Error>> + Send;

    /// Retrieves all garbling table commitments.
    fn get_garbling_table_commitments(
        &self,
    ) -> impl Future<Output = Result<Option<AllGarblingTableCommitments>, Self::Error>> + Send;

    /// Retrieves the challenge indices used in verification.
    fn get_challenge_indices(
        &self,
    ) -> impl Future<Output = Result<Option<ChallengeIndices>, Self::Error>> + Send;

    /// Retrieves input shares for opened circuits.
    fn get_opened_input_shares(
        &self,
    ) -> impl Future<Output = Result<Option<OpenedInputShares>, Self::Error>> + Send;

    /// Retrieves reserved setup input shares.
    fn get_reserved_setup_input_shares(
        &self,
    ) -> impl Future<Output = Result<Option<ReservedSetupInputShares>, Self::Error>> + Send;

    /// Retrieves output shares for opened circuits.
    fn get_opened_output_shares(
        &self,
    ) -> impl Future<Output = Result<Option<OpenedOutputShares>, Self::Error>> + Send;

    /// Retrieves garbling seeds for opened circuits.
    fn get_opened_garbling_seeds(
        &self,
    ) -> impl Future<Output = Result<Option<OpenedGarblingSeeds>, Self::Error>> + Send;

    /// Retrieves sighashes for a specific deposit.
    fn get_deposit_sighashes(
        &self,
        deposit_id: &DepositId,
    ) -> impl Future<Output = Result<Option<Sighashes>, Self::Error>> + Send;

    /// Retrieves input data for a specific deposit.
    fn get_deposit_inputs(
        &self,
        deposit_id: &DepositId,
    ) -> impl Future<Output = Result<Option<DepositInputs>, Self::Error>> + Send;

    /// Retrieves withdrawal input data for a specific deposit.
    fn get_withdrawal_inputs(
        &self,
        deposit_id: &DepositId,
    ) -> impl Future<Output = Result<Option<WithdrawalInputs>, Self::Error>> + Send;

    /// Retrieves deposit adaptor signatures for a specific deposit.
    fn get_deposit_adaptors(
        &self,
        deposit_id: &DepositId,
    ) -> impl Future<Output = Result<Option<DepositAdaptors>, Self::Error>> + Send;

    /// Retrieves withdrawal adaptor signatures for a specific deposit.
    fn get_withdrawal_adaptors(
        &self,
        deposit_id: &DepositId,
    ) -> impl Future<Output = Result<Option<WithdrawalAdaptors>, Self::Error>> + Send;

    /// Retrieves completed signatures for a specific deposit.
    fn get_completed_signatures(
        &self,
        deposit_id: &DepositId,
    ) -> impl Future<Output = Result<Option<CompletedSignatures>, Self::Error>> + Send;

    /// Retrieves the AES-128 key for a specific garbling circuit index.
    fn get_aes128_key(
        &self,
        index: Index,
    ) -> impl Future<Output = Result<Option<[u8; 16]>, Self::Error>> + Send;

    /// Retrieves the public S value for a specific garbling circuit index.
    fn get_public_s(
        &self,
        index: Index,
    ) -> impl Future<Output = Result<Option<[u8; 16]>, Self::Error>> + Send;

    /// Retrieves the constant-false wire label for a specific garbling circuit index.
    fn get_constant_zero_label(
        &self,
        index: Index,
    ) -> impl Future<Output = Result<Option<[u8; 16]>, Self::Error>> + Send;

    /// Retrieves the constant-true wire label for a specific garbling circuit index.
    fn get_constant_one_label(
        &self,
        index: Index,
    ) -> impl Future<Output = Result<Option<[u8; 16]>, Self::Error>> + Send;

    /// Retrieves the output label ciphertext for an unopened (evaluation) circuit.
    fn get_output_label_ct(
        &self,
        index: Index,
    ) -> impl Future<Output = Result<Option<Byte32>, Self::Error>> + Send;
}

/// Mutable access to evaluator state storage.
pub trait StateMut: StateRead {
    /// Stores the root evaluator state.
    fn put_root_state(
        &mut self,
        state: &EvaluatorState,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Stores the state for a specific deposit.
    fn put_deposit(
        &mut self,
        deposit_id: &DepositId,
        deposit_state: &DepositState,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Stores a chunk of input polynomial commitments for a specific wire.
    fn put_input_polynomial_commitments_chunk(
        &mut self,
        wire_idx: u16,
        commitments: &WideLabelWirePolynomialCommitments,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Stores the commitment to output polynomial.
    fn put_output_polynomial_commitment(
        &mut self,
        commitment: &OutputPolynomialCommitment,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Stores all garbling table commitments.
    fn put_garbling_table_commitments(
        &mut self,
        commitments: &AllGarblingTableCommitments,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Stores the challenge indices used in verification.
    fn put_challenge_indices(
        &mut self,
        challenge_idxs: &ChallengeIndices,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Stores input shares for opened circuits, one chunk per circuit.
    fn put_opened_input_shares_chunk(
        &mut self,
        opened_ckt_idx: u16,
        input_shares: &CircuitInputShares,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Stores reserved setup input shares.
    fn put_reserved_setup_input_shares(
        &mut self,
        reserved_setup_input_shares: &ReservedSetupInputShares,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Stores output shares for opened circuits.
    fn put_opened_output_shares(
        &mut self,
        opened_output_shares: &OpenedOutputShares,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Stores garbling seeds for opened circuits.
    fn put_opened_garbling_seeds(
        &mut self,
        opened_garbling_seeds: &OpenedGarblingSeeds,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Stores sighashes for a specific deposit.
    fn put_sighashes_for_deposit(
        &mut self,
        deposit_id: &DepositId,
        sighashes: &Sighashes,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Stores input data for a specific deposit.
    fn put_inputs_for_deposit(
        &mut self,
        deposit_id: &DepositId,
        inputs: &DepositInputs,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Stores deposit adaptor signatures for a specific deposit.
    fn put_deposit_adaptors(
        &mut self,
        deposit_id: &DepositId,
        deposit_adaptors: &DepositAdaptors,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Stores a chunk of withdrawal adaptor signatures for a specific deposit.
    fn put_withdrawal_adaptors_chunk(
        &mut self,
        deposit_id: &DepositId,
        chunk_idx: u8,
        withdrawal_adaptors: &WithdrawalAdaptorsChunk,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Stores withdrawal input data for a specific deposit.
    fn put_withdrawal_inputs(
        &mut self,
        deposit_id: &DepositId,
        withdrawal_input: &WithdrawalInputs,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Stores completed signatures for a specific deposit.
    fn put_completed_signatures(
        &mut self,
        deposit_id: &DepositId,
        signatures: &CompletedSignatures,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Stores AES-128 keys for all garbling circuit indices.
    fn put_all_aes128_keys(
        &mut self,
        keys: &crate::HeapArray<[u8; 16], { mosaic_common::constants::N_CIRCUITS }>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Stores public S values for all garbling circuit indices.
    fn put_all_public_s(
        &mut self,
        values: &crate::HeapArray<[u8; 16], { mosaic_common::constants::N_CIRCUITS }>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Stores constant-false wire labels for all garbling circuit indices.
    fn put_all_constant_zero_labels(
        &mut self,
        labels: &crate::HeapArray<[u8; 16], { mosaic_common::constants::N_CIRCUITS }>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Stores constant-true wire labels for all garbling circuit indices.
    fn put_all_constant_one_labels(
        &mut self,
        labels: &crate::HeapArray<[u8; 16], { mosaic_common::constants::N_CIRCUITS }>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Stores output label ciphertexts for the unopened (evaluation) circuits.
    fn put_unchallenged_output_label_cts(
        &mut self,
        indices: &EvaluationIndices,
        cts: &crate::HeapArray<Byte32, { mosaic_common::constants::N_EVAL_CIRCUITS }>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}
