use std::{error::Error, fmt::Debug};

use futures::Stream;

use super::{DepositState, GarblerState};
use crate::{
    AdaptorMsgChunk, AllAes128Keys, AllConstOneLabels, AllConstZeroLabels,
    AllGarblingTableCommitments, AllOutputLabelCts, AllPublicSValues, ChallengeIndices,
    CircuitInputShares, CircuitOutputShare, CompletedSignatures, DepositAdaptors, DepositId,
    DepositInputs, GarblingTableCommitment, Index, InputShares, OutputPolynomialCommitment,
    OutputShares, ReservedInputShares, Sighashes, WideLabelWirePolynomialCommitments,
    WithdrawalAdaptors, WithdrawalInputs, state_machine::garbler::GarblingMetadata,
};

/// Read-only access to garbler state storage.
pub trait StateRead {
    /// Error type used by state operations.
    type Error: Error + Debug + Send + 'static;

    /// Retrieves the root garbler state.
    fn get_root_state(
        &self,
    ) -> impl Future<Output = Result<Option<GarblerState>, Self::Error>> + Send;

    /// Retrieves the state for a specific deposit.
    fn get_deposit(
        &self,
        deposit_id: &DepositId,
    ) -> impl Future<Output = Result<Option<DepositState>, Self::Error>> + Send;

    /// Streams all deposits with their IDs and states.
    fn stream_all_deposits(
        &self,
    ) -> impl Stream<Item = Result<(DepositId, DepositState), Self::Error>> + Send;

    /// Retrieves commitments to input polynomials for all wide label values for a single wire.
    fn get_input_polynomial_commitment_by_wire(
        &self,
        wire: u16,
    ) -> impl Future<Output = Result<Option<WideLabelWirePolynomialCommitments>, Self::Error>> + Send;

    /// Retrieves the commitment to output polynomial.
    fn get_output_polynomial_commitment(
        &self,
    ) -> impl Future<Output = Result<Option<OutputPolynomialCommitment>, Self::Error>> + Send;

    /// Retrieves input shares for all circuits.
    fn get_input_shares(
        &self,
    ) -> impl Future<Output = Result<Option<InputShares>, Self::Error>> + Send;

    /// Retrieves output shares for all circuits.
    fn get_output_shares(
        &self,
    ) -> impl Future<Output = Result<Option<OutputShares>, Self::Error>> + Send;

    /// Retrieves input shares for a single circuit.
    fn get_input_shares_for_circuit(
        &self,
        circuit_idx: &Index,
    ) -> impl Future<Output = Result<Option<CircuitInputShares>, Self::Error>> + Send;

    /// Retrieves output shares for a single circuit.
    fn get_output_share_for_circuit(
        &self,
        circuit_idx: &Index,
    ) -> impl Future<Output = Result<Option<CircuitOutputShare>, Self::Error>> + Send;

    /// Retrieves reserved input shares.
    fn get_reserved_input_shares(
        &self,
    ) -> impl Future<Output = Result<Option<ReservedInputShares>, Self::Error>> + Send;

    /// Retrieves garbling table commitment for a specific circuit index.
    fn get_garbling_table_commitment(
        &self,
        index: Index,
    ) -> impl Future<Output = Result<Option<GarblingTableCommitment>, Self::Error>> + Send;

    /// Retrieves all garbling table commitments.
    fn get_all_garbling_table_commitments(
        &self,
    ) -> impl Future<Output = Result<Option<AllGarblingTableCommitments>, Self::Error>> + Send;

    /// Retrieves all aes128 keys.
    fn get_all_aes128_keys(
        &self,
    ) -> impl Future<Output = Result<Option<AllAes128Keys>, Self::Error>> + Send;

    /// Retrieves all public S values.
    fn get_all_public_s_values(
        &self,
    ) -> impl Future<Output = Result<Option<AllPublicSValues>, Self::Error>> + Send;

    /// Retrieves all constant zero labels.
    fn get_all_constant_zero_labels(
        &self,
    ) -> impl Future<Output = Result<Option<AllConstZeroLabels>, Self::Error>> + Send;

    /// Retrieves all constant one labels.
    fn get_all_constant_one_labels(
        &self,
    ) -> impl Future<Output = Result<Option<AllConstOneLabels>, Self::Error>> + Send;

    /// Retrieves all Output label ciphertexts.
    fn get_all_output_label_cts(
        &self,
    ) -> impl Future<Output = Result<Option<AllOutputLabelCts>, Self::Error>> + Send;

    /// Retrieves the challenge indices used in verification.
    fn get_challenge_indices(
        &self,
    ) -> impl Future<Output = Result<Option<ChallengeIndices>, Self::Error>> + Send;

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
    fn get_withdrawal_input(
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
}

/// Mutable access to garbler state storage.
pub trait StateMut: StateRead {
    /// Stores the root garbler state.
    fn put_root_state(
        &mut self,
        state: &GarblerState,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Stores the state for a specific deposit.
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

    /// Stores the commitment to output polynomial (~5KB).
    fn put_output_polynomial_commitment(
        &mut self,
        commitments: &OutputPolynomialCommitment,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Stores input and output shares for a specific circuit index.
    fn put_shares_for_index(
        &mut self,
        index: Index,
        input_shares: &CircuitInputShares,
        output_share: &CircuitOutputShare,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Stores garbling table commitment for a specific circuit index.
    fn put_garbling_table_commitment(
        &mut self,
        index: Index,
        commitments: &GarblingTableCommitment,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Store garbling table metadata for a specific circuit index.
    fn put_garbling_table_metadata(
        &mut self,
        index: Index,
        metadata: &GarblingMetadata,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Stores the challenge indices used in verification.
    fn put_challenge_indices(
        &mut self,
        challenge_idxs: &ChallengeIndices,
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

    /// Stores an adaptor message chunk for a specific deposit.
    fn put_adaptor_msg_chunk_for_deposit(
        &mut self,
        deposit_id: &DepositId,
        adaptor_chunk: &AdaptorMsgChunk,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Stores withdrawal input data for a specific deposit.
    fn put_withdrawal_input(
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
}
