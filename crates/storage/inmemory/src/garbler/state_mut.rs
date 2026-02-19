use mosaic_cac_protocol::garbler::{
    deposit::DepositState, root_state::GarblerState, state::StateMut,
};
use mosaic_cac_types::{
    AdaptorMsgChunk, ChallengeIndices, CircuitInputShares, CircuitOutputShare, CompletedSignatures,
    DepositId, DepositInputs, GarblingTableCommitment, Index, OutputPolynomialCommitment,
    Sighashes, WideLabelWirePolynomialCommitments, WithdrawalInputs,
};

use super::StoredGarblerState;

impl StateMut for StoredGarblerState {
    async fn put_root_state(&mut self, state: &GarblerState) -> Result<(), Self::Error> {
        self.state = state.clone();
        Ok(())
    }

    async fn put_deposit(
        &mut self,
        deposit_id: DepositId,
        deposit_state: &DepositState,
    ) -> Result<(), Self::Error> {
        let deposit_data = self.get_deposit_mut_or_default(&deposit_id);
        deposit_data.state = Some(deposit_state.clone());
        Ok(())
    }

    async fn put_input_polynomial_commitments_chunk(
        &mut self,
        wire_idx: u16,
        commitments: &WideLabelWirePolynomialCommitments,
    ) -> Result<(), Self::Error> {
        self.input_polynomial_commitments
            .insert(wire_idx as usize, commitments.clone());
        Ok(())
    }

    async fn put_output_polynomial_commitment(
        &mut self,
        commitment: &OutputPolynomialCommitment,
    ) -> Result<(), Self::Error> {
        self.output_polynomial_commitment = Some(commitment.clone());
        Ok(())
    }

    async fn put_shares_for_index(
        &mut self,
        index: Index,
        input_shares: &CircuitInputShares,
        output_share: &CircuitOutputShare,
    ) -> Result<(), Self::Error> {
        self.input_shares.insert(index.get(), input_shares.clone());
        self.output_shares.insert(index.get(), output_share.clone());
        Ok(())
    }

    async fn put_garbling_table_commitment(
        &mut self,
        index: Index,
        commitments: &GarblingTableCommitment,
    ) -> Result<(), Self::Error> {
        self.gt_commitments.insert(index.get(), *commitments);
        Ok(())
    }

    async fn put_challenge_indices(
        &mut self,
        challenge_idxs: &ChallengeIndices,
    ) -> Result<(), Self::Error> {
        self.challenge_indices = Some(challenge_idxs.clone());
        Ok(())
    }

    async fn put_sighashes_for_deposit(
        &mut self,
        deposit_id: &DepositId,
        sighashes: &Sighashes,
    ) -> Result<(), Self::Error> {
        let deposit_data = self.get_deposit_mut_or_default(deposit_id);
        deposit_data.sighashes = Some(sighashes.clone());
        Ok(())
    }

    async fn put_inputs_for_deposit(
        &mut self,
        deposit_id: &DepositId,
        inputs: &DepositInputs,
    ) -> Result<(), Self::Error> {
        let deposit_data = self.get_deposit_mut_or_default(deposit_id);
        deposit_data.deposit_inputs = Some(*inputs);
        Ok(())
    }

    async fn put_adaptor_msg_chunk_for_deposit(
        &mut self,
        deposit_id: &DepositId,
        adaptor_chunk: &AdaptorMsgChunk,
    ) -> Result<(), Self::Error> {
        let deposit_data = self.get_deposit_mut_or_default(deposit_id);
        deposit_data
            .deposit_adaptors
            .insert(adaptor_chunk.chunk_index, adaptor_chunk.deposit_adaptor);
        deposit_data.withdrawal_adaptor_chunks.insert(
            adaptor_chunk.chunk_index,
            adaptor_chunk.withdrawal_adaptors.clone(),
        );
        Ok(())
    }

    async fn put_withdrawal_input(
        &mut self,
        deposit_id: &DepositId,
        withdrawal_input: &WithdrawalInputs,
    ) -> Result<(), Self::Error> {
        let deposit_data = self.get_deposit_mut_or_default(deposit_id);
        deposit_data.withdrawal_inputs = Some(*withdrawal_input);
        Ok(())
    }

    async fn put_completed_signatures(
        &mut self,
        deposit_id: &DepositId,
        signatures: &CompletedSignatures,
    ) -> Result<(), Self::Error> {
        let deposit_data = self.get_deposit_mut_or_default(deposit_id);
        deposit_data.completed_sigs = Some(signatures.clone());
        Ok(())
    }
}
