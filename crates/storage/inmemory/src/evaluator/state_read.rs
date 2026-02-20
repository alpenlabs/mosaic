use futures::{
    Stream,
    stream::{self, StreamExt},
};
use mosaic_cac_types::{
    AllGarblingTableCommitments, ChallengeIndices, CompletedSignatures, DepositAdaptors, DepositId,
    DepositInputs, HeapArray, InputPolynomialCommitments, OpenedGarblingSeeds, OpenedInputShares,
    OpenedOutputShares, OutputPolynomialCommitment, ReservedSetupInputShares, Sighashes,
    WithdrawalAdaptors, WithdrawalInputs,
    state_machine::evaluator::{DepositState, EvaluatorState, StateRead},
};
use mosaic_common::constants::{N_ADAPTOR_MSG_CHUNKS, N_INPUT_WIRES};

use super::StoredEvaluatorState;
use crate::error::DbError;

impl StateRead for StoredEvaluatorState {
    type Error = DbError;

    async fn get_root_state(&self) -> Result<Option<EvaluatorState>, Self::Error> {
        Ok(Some(self.state.clone()))
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
                .ok_or_else(|| DbError::state_inconsistency("missing expected input share"))?;

            input_commitments.push(commitment);
        }

        Ok(Some(HeapArray::from_vec(input_commitments)))
    }

    async fn get_output_polynomial_commitment(
        &self,
    ) -> Result<Option<OutputPolynomialCommitment>, Self::Error> {
        Ok(self.output_polynomial_commitment.clone())
    }

    async fn get_garbling_table_commitments(
        &self,
    ) -> Result<Option<AllGarblingTableCommitments>, Self::Error> {
        Ok(self.gt_commitments.clone())
    }

    async fn get_challenge_indices(&self) -> Result<Option<ChallengeIndices>, Self::Error> {
        Ok(self.challenge_indices.clone())
    }

    async fn get_opened_input_shares(&self) -> Result<Option<OpenedInputShares>, Self::Error> {
        if self.opened_input_shares.is_empty() {
            return Ok(None);
        }
        let challenge_indices = self
            .get_challenge_indices()
            .await?
            .ok_or_else(|| DbError::state_inconsistency("expected challenge indices"))?;
        let mut opened_input_shares_vec = Vec::new();
        for index in challenge_indices {
            let input_shares = self
                .opened_input_shares
                .get(&index.get())
                .cloned()
                .ok_or_else(|| DbError::state_inconsistency("expected opened input share"))?;

            opened_input_shares_vec.push(input_shares);
        }

        Ok(Some(HeapArray::from_vec(opened_input_shares_vec)))
    }

    async fn get_reserved_setup_input_shares(
        &self,
    ) -> Result<Option<ReservedSetupInputShares>, Self::Error> {
        Ok(self.reserved_setup_input_shares.clone())
    }

    async fn get_opened_output_shares(&self) -> Result<Option<OpenedOutputShares>, Self::Error> {
        Ok(self.opened_output_shares.clone())
    }

    async fn get_opened_garbling_seeds(&self) -> Result<Option<OpenedGarblingSeeds>, Self::Error> {
        Ok(self.opened_garbling_seeds.clone())
    }

    async fn get_deposit_sighashes(
        &self,
        deposit_id: &DepositId,
    ) -> Result<Option<Sighashes>, Self::Error> {
        let deposit_data = self.get_deposit_or_err(deposit_id)?;

        Ok(deposit_data.sighashes.clone())
    }

    async fn get_deposit_adaptors(
        &self,
        deposit_id: &DepositId,
    ) -> Result<Option<DepositAdaptors>, Self::Error> {
        let deposit_data = self.get_deposit_or_err(deposit_id)?;

        Ok(deposit_data.deposit_adaptors.clone())
    }

    async fn get_withdrawal_adaptors(
        &self,
        deposit_id: &DepositId,
    ) -> Result<Option<WithdrawalAdaptors>, Self::Error> {
        let deposit_data = self.get_deposit_or_err(deposit_id)?;

        if deposit_data.withdrawal_adaptors.is_empty() {
            return Ok(None);
        }

        let mut withdrawal_adaptor_vec = Vec::new();

        for idx in 0..N_ADAPTOR_MSG_CHUNKS {
            let chunk = deposit_data
                .withdrawal_adaptors
                .get(&(idx as u8))
                .ok_or_else(|| DbError::state_inconsistency("expected withdrawal adaptor chunk"))?;

            withdrawal_adaptor_vec.append(&mut chunk.clone().to_vec());
        }

        Ok(Some(HeapArray::from_vec(withdrawal_adaptor_vec)))
    }

    async fn get_withdrawal_inputs(
        &self,
        deposit_id: &DepositId,
    ) -> Result<Option<WithdrawalInputs>, Self::Error> {
        let deposit_data = self.get_deposit_or_err(deposit_id)?;

        Ok(deposit_data.withdrawal_inputs)
    }

    async fn get_completed_signatures(
        &self,
        deposit_id: &DepositId,
    ) -> Result<Option<CompletedSignatures>, Self::Error> {
        let deposit_data = self.get_deposit_or_err(deposit_id)?;
        Ok(deposit_data.completed_sigs.clone())
    }

    async fn get_deposit_inputs(
        &self,
        deposit_id: &DepositId,
    ) -> Result<Option<DepositInputs>, Self::Error> {
        let deposit_data = self.get_deposit_or_err(deposit_id)?;

        Ok(deposit_data.deposit_inputs)
    }
}
