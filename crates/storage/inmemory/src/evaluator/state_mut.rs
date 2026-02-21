use mosaic_cac_types::{
    AllGarblingTableCommitments, ChallengeIndices, CircuitInputShares, CompletedSignatures,
    DepositAdaptors, DepositId, DepositInputs, OpenedGarblingSeeds, OpenedOutputShares,
    OutputPolynomialCommitment, ReservedSetupInputShares, Sighashes,
    WideLabelWirePolynomialCommitments, WithdrawalAdaptorsChunk, WithdrawalInputs,
    state_machine::evaluator::{DepositState, EvaluatorState, StateMut},
};

use super::StoredEvaluatorState;

impl StateMut for StoredEvaluatorState {
    async fn put_root_state(&mut self, state: &EvaluatorState) -> Result<(), Self::Error> {
        self.state = state.clone();
        Ok(())
    }

    async fn put_deposit(
        &mut self,
        deposit_id: &DepositId,
        deposit_state: &DepositState,
    ) -> Result<(), Self::Error> {
        let deposit_data = self.get_deposit_mut_or_default(deposit_id);

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

    async fn put_garbling_table_commitments(
        &mut self,
        commitments: &AllGarblingTableCommitments,
    ) -> Result<(), Self::Error> {
        self.gt_commitments = Some(commitments.clone());

        Ok(())
    }

    async fn put_challenge_indices(
        &mut self,
        challenge_idxs: &ChallengeIndices,
    ) -> Result<(), Self::Error> {
        self.challenge_indices = Some(challenge_idxs.clone());

        Ok(())
    }

    async fn put_opened_input_shares_chunk(
        &mut self,
        opened_ckt_idx: u16,
        input_shares: &CircuitInputShares,
    ) -> Result<(), Self::Error> {
        self.opened_input_shares
            .insert(opened_ckt_idx as usize, input_shares.clone());

        Ok(())
    }

    async fn put_reserved_setup_input_shares(
        &mut self,
        reserved_setup_input_shares: &ReservedSetupInputShares,
    ) -> Result<(), Self::Error> {
        self.reserved_setup_input_shares = Some(reserved_setup_input_shares.clone());

        Ok(())
    }

    async fn put_opened_output_shares(
        &mut self,
        opened_output_shares: &OpenedOutputShares,
    ) -> Result<(), Self::Error> {
        self.opened_output_shares = Some(opened_output_shares.clone());

        Ok(())
    }

    async fn put_opened_garbling_seeds(
        &mut self,
        opened_garbling_seeds: &OpenedGarblingSeeds,
    ) -> Result<(), Self::Error> {
        self.opened_garbling_seeds = Some(opened_garbling_seeds.clone());

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

    async fn put_deposit_adaptors(
        &mut self,
        deposit_id: &DepositId,
        deposit_adaptors: &DepositAdaptors,
    ) -> Result<(), Self::Error> {
        let deposit_data = self.get_deposit_mut_or_default(deposit_id);

        deposit_data.deposit_adaptors = Some(deposit_adaptors.clone());

        Ok(())
    }

    async fn put_withdrawal_inputs(
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

    async fn put_withdrawal_adaptors_chunk(
        &mut self,
        deposit_id: &DepositId,
        chunk_idx: u8,
        withdrawal_adaptors: &WithdrawalAdaptorsChunk,
    ) -> Result<(), Self::Error> {
        let deposit_data = self.get_deposit_mut_or_default(deposit_id);

        deposit_data
            .withdrawal_adaptors
            .insert(chunk_idx, withdrawal_adaptors.clone());

        Ok(())
    }

    async fn put_all_constant_zero_labels(
        &mut self,
        labels: &mosaic_cac_types::HeapArray<[u8; 16], { mosaic_common::constants::N_CIRCUITS }>,
    ) -> Result<(), Self::Error> {
        for (i, label) in labels.iter().enumerate() {
            self.constant_zero_labels.insert(i, *label);
        }
        Ok(())
    }

    async fn put_all_constant_one_labels(
        &mut self,
        labels: &mosaic_cac_types::HeapArray<[u8; 16], { mosaic_common::constants::N_CIRCUITS }>,
    ) -> Result<(), Self::Error> {
        for (i, label) in labels.iter().enumerate() {
            self.constant_one_labels.insert(i, *label);
        }
        Ok(())
    }

    async fn put_all_aes128_keys(
        &mut self,
        keys: &mosaic_cac_types::HeapArray<[u8; 16], { mosaic_common::constants::N_CIRCUITS }>,
    ) -> Result<(), Self::Error> {
        for (i, key) in keys.iter().enumerate() {
            self.aes128_keys.insert(i, *key);
        }
        Ok(())
    }

    async fn put_all_public_s(
        &mut self,
        values: &mosaic_cac_types::HeapArray<[u8; 16], { mosaic_common::constants::N_CIRCUITS }>,
    ) -> Result<(), Self::Error> {
        for (i, val) in values.iter().enumerate() {
            self.public_s_values.insert(i, *val);
        }
        Ok(())
    }

    async fn put_unchallenged_output_label_cts(
        &mut self,
        cts: &mosaic_cac_types::HeapArray<
            mosaic_common::Byte32,
            { mosaic_common::constants::N_EVAL_CIRCUITS },
        >,
    ) -> Result<(), Self::Error> {
        for (i, ct) in cts.iter().enumerate() {
            self.output_label_cts.insert(i, *ct);
        }
        Ok(())
    }
}
