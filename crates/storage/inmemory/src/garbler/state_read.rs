use futures::{
    Stream,
    stream::{self, StreamExt},
};
use mosaic_cac_types::{
    AllAes128Keys, AllConstOneLabels, AllConstZeroLabels, AllGarblingTableCommitments,
    AllOutputLabelCts, AllPublicSValues, ChallengeIndices, CircuitInputShares, CircuitOutputShare,
    CompletedSignatures, DepositAdaptors, DepositId, DepositInputs, GarblingTableCommitment,
    HeapArray, Index, InputPolynomialCommitments, InputShares, OutputPolynomialCommitment,
    OutputShares, ReservedInputShares, Sighashes, WithdrawalAdaptors, WithdrawalInputs,
    state_machine::garbler::{DepositState, GarblerState, StateRead},
};
use mosaic_common::constants::{N_ADAPTOR_MSG_CHUNKS, N_CIRCUITS, N_INPUT_WIRES};

use super::StoredGarblerState;
use crate::error::DbError;

impl StateRead for StoredGarblerState {
    type Error = DbError;

    async fn get_root_state(&self) -> Result<Option<GarblerState>, Self::Error> {
        Ok(self.state.clone())
    }

    async fn get_deposit(
        &self,
        deposit_id: &DepositId,
    ) -> Result<Option<DepositState>, Self::Error> {
        let Some(deposit_data) = self.deposits.get(deposit_id) else {
            return Ok(None);
        };

        Ok(deposit_data.state.clone())
    }

    fn stream_all_deposits(
        &self,
    ) -> impl Stream<Item = Result<(DepositId, DepositState), Self::Error>> + Send {
        let deposits: Vec<_> = self
            .deposits
            .iter()
            .filter_map(|(id, deposit_data)| deposit_data.state.clone().map(|state| (*id, state)))
            .collect();

        stream::iter(deposits).map(Ok)
    }

    async fn get_input_polynomial_commitments(
        &self,
    ) -> Result<Option<InputPolynomialCommitments>, Self::Error> {
        if self.input_polynomial_commitments.is_empty() {
            return Ok(None);
        }
        let mut input_commitments = Vec::new();
        for idx in 0..N_INPUT_WIRES {
            let commitment = self
                .input_polynomial_commitments
                .get(&idx)
                .cloned()
                .ok_or_else(|| DbError::state_inconsistency("missing expected input commitment"))?;

            input_commitments.push(commitment);
        }

        Ok(Some(HeapArray::from_vec(input_commitments)))
    }

    async fn get_output_polynomial_commitment(
        &self,
    ) -> Result<Option<OutputPolynomialCommitment>, Self::Error> {
        Ok(self.output_polynomial_commitment.clone())
    }

    async fn get_input_shares(&self) -> Result<Option<InputShares>, Self::Error> {
        if self.input_shares.is_empty() {
            return Ok(None);
        }

        let mut input_shares_vec = Vec::new();
        for ckt_idx in 0..N_CIRCUITS + 1 {
            let input_shares = self
                .input_shares
                .get(&ckt_idx)
                .cloned()
                .ok_or_else(|| DbError::state_inconsistency("missing expected input share"))?;
            input_shares_vec.push(input_shares);
        }

        Ok(Some(HeapArray::from_vec(input_shares_vec)))
    }

    async fn get_output_shares(&self) -> Result<Option<OutputShares>, Self::Error> {
        if self.output_shares.is_empty() {
            return Ok(None);
        }

        let mut output_shares_vec = Vec::new();
        for ckt_idx in 0..N_CIRCUITS + 1 {
            let output_shares = self
                .output_shares
                .get(&ckt_idx)
                .cloned()
                .ok_or_else(|| DbError::state_inconsistency("missing expected output share"))?;
            output_shares_vec.push(output_shares);
        }

        Ok(Some(HeapArray::from_vec(output_shares_vec)))
    }

    async fn get_input_shares_for_circuit(
        &self,
        circuit_idx: &Index,
    ) -> Result<Option<CircuitInputShares>, Self::Error> {
        Ok(self.input_shares.get(&circuit_idx.get()).cloned())
    }

    async fn get_output_share_for_circuit(
        &self,
        circuit_idx: &Index,
    ) -> Result<Option<CircuitOutputShare>, Self::Error> {
        Ok(self.output_shares.get(&circuit_idx.get()).cloned())
    }

    async fn get_reserved_input_shares(&self) -> Result<Option<ReservedInputShares>, Self::Error> {
        Ok(self.input_shares.get(&0).cloned())
    }

    async fn get_garbling_table_commitment(
        &self,
        index: Index,
    ) -> Result<Option<GarblingTableCommitment>, Self::Error> {
        let zero_offset_index = index
            .get()
            .checked_sub(1)
            .ok_or(DbError::UnexpectedZeroIndex)?;

        Ok(self.gt_commitments.get(&zero_offset_index).cloned())
    }

    async fn get_all_garbling_table_commitments(
        &self,
    ) -> Result<Option<AllGarblingTableCommitments>, Self::Error> {
        if self.gt_commitments.is_empty() {
            return Ok(None);
        }

        let mut commitments = Vec::new();
        for ckt_idx in 0..N_CIRCUITS {
            let commitment = self.gt_commitments.get(&ckt_idx).cloned().ok_or_else(|| {
                DbError::state_inconsistency("missing expected garbling table commitment")
            })?;
            commitments.push(commitment);
        }

        Ok(Some(HeapArray::from_vec(commitments)))
    }

    async fn get_all_aes128_keys(&self) -> Result<Option<AllAes128Keys>, Self::Error> {
        if self.aes128_keys.is_empty() {
            return Ok(None);
        }

        let mut values = Vec::new();
        for ckt_idx in 0..N_CIRCUITS {
            let value = self.aes128_keys.get(&ckt_idx).cloned().ok_or_else(|| {
                DbError::state_inconsistency("missing expected garbling table commitment")
            })?;
            values.push(value);
        }

        Ok(Some(HeapArray::from_vec(values)))
    }

    async fn get_all_public_s_values(&self) -> Result<Option<AllPublicSValues>, Self::Error> {
        if self.public_s_values.is_empty() {
            return Ok(None);
        }

        let mut values = Vec::new();
        for ckt_idx in 0..N_CIRCUITS {
            let value = self.public_s_values.get(&ckt_idx).cloned().ok_or_else(|| {
                DbError::state_inconsistency("missing expected garbling metadata public S value")
            })?;
            values.push(value);
        }

        Ok(Some(HeapArray::from_vec(values)))
    }

    async fn get_all_constant_zero_labels(
        &self,
    ) -> Result<Option<AllConstZeroLabels>, Self::Error> {
        if self.constant_zero_labels.is_empty() {
            return Ok(None);
        }

        let mut values = Vec::new();
        for ckt_idx in 0..N_CIRCUITS {
            let value = self
                .constant_zero_labels
                .get(&ckt_idx)
                .cloned()
                .ok_or_else(|| {
                    DbError::state_inconsistency(
                        "missing expected garbling metadata constant zero label",
                    )
                })?;
            values.push(value);
        }

        Ok(Some(HeapArray::from_vec(values)))
    }

    async fn get_all_constant_one_labels(&self) -> Result<Option<AllConstOneLabels>, Self::Error> {
        if self.constant_one_labels.is_empty() {
            return Ok(None);
        }

        let mut values = Vec::new();
        for ckt_idx in 0..N_CIRCUITS {
            let value = self
                .constant_one_labels
                .get(&ckt_idx)
                .cloned()
                .ok_or_else(|| {
                    DbError::state_inconsistency(
                        "missing expected garbling metadata constant one label",
                    )
                })?;
            values.push(value);
        }

        Ok(Some(HeapArray::from_vec(values)))
    }

    async fn get_all_output_label_cts(&self) -> Result<Option<AllOutputLabelCts>, Self::Error> {
        if self.output_label_cts.is_empty() {
            return Ok(None);
        }

        let mut values = Vec::new();
        for ckt_idx in 0..N_CIRCUITS {
            let value = self
                .output_label_cts
                .get(&ckt_idx)
                .cloned()
                .ok_or_else(|| {
                    DbError::state_inconsistency(
                        "missing expected garbling metadata output label ciphertext",
                    )
                })?;
            values.push(value);
        }

        Ok(Some(HeapArray::from_vec(values)))
    }

    async fn get_challenge_indices(&self) -> Result<Option<ChallengeIndices>, Self::Error> {
        Ok(self.challenge_indices.clone())
    }

    async fn get_deposit_sighashes(
        &self,
        deposit_id: &DepositId,
    ) -> Result<Option<Sighashes>, Self::Error> {
        let deposit_data = self.get_deposit_or_err(deposit_id)?;
        Ok(deposit_data.sighashes.clone())
    }

    async fn get_deposit_inputs(
        &self,
        deposit_id: &DepositId,
    ) -> Result<Option<DepositInputs>, Self::Error> {
        let deposit_data = self.get_deposit_or_err(deposit_id)?;
        Ok(deposit_data.deposit_inputs)
    }

    async fn get_withdrawal_input(
        &self,
        deposit_id: &DepositId,
    ) -> Result<Option<WithdrawalInputs>, Self::Error> {
        let deposit_data = self.get_deposit_or_err(deposit_id)?;
        Ok(deposit_data.withdrawal_inputs)
    }

    async fn get_deposit_adaptors(
        &self,
        deposit_id: &DepositId,
    ) -> Result<Option<DepositAdaptors>, Self::Error> {
        let deposit_data = self.get_deposit_or_err(deposit_id)?;

        if deposit_data.deposit_adaptors.is_empty() {
            return Ok(None);
        }

        let mut deposit_adaptors_vec = Vec::new();
        for chunk_idx in 0..N_ADAPTOR_MSG_CHUNKS {
            let deposit_adaptor = deposit_data
                .deposit_adaptors
                .get(&(chunk_idx as u8))
                .cloned()
                .ok_or_else(|| DbError::state_inconsistency("expected deposit adaptor"))?;
            deposit_adaptors_vec.push(deposit_adaptor);
        }

        Ok(Some(HeapArray::from_vec(deposit_adaptors_vec)))
    }

    async fn get_withdrawal_adaptors(
        &self,
        deposit_id: &DepositId,
    ) -> Result<Option<WithdrawalAdaptors>, Self::Error> {
        let deposit_data = self.get_deposit_or_err(deposit_id)?;

        if deposit_data.withdrawal_adaptor_chunks.is_empty() {
            return Ok(None);
        }

        let mut withdrawal_adaptors_vec = Vec::new();
        for chunk_idx in 0..N_ADAPTOR_MSG_CHUNKS {
            let chunk = deposit_data
                .withdrawal_adaptor_chunks
                .get(&(chunk_idx as u8))
                .cloned()
                .ok_or_else(|| DbError::state_inconsistency("expected withdrawal adaptor chunk"))?;
            withdrawal_adaptors_vec.append(&mut chunk.to_vec());
        }

        Ok(Some(HeapArray::from_vec(withdrawal_adaptors_vec)))
    }

    async fn get_completed_signatures(
        &self,
        deposit_id: &DepositId,
    ) -> Result<Option<CompletedSignatures>, Self::Error> {
        let deposit_data = self.get_deposit_or_err(deposit_id)?;
        Ok(deposit_data.completed_sigs.clone())
    }
}
