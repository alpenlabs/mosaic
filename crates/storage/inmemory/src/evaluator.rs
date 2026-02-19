//! In-memory storage implementation for evaluator state.

use std::collections::{BTreeMap, HashMap};

use futures::{
    Stream,
    stream::{self, StreamExt},
};
use mosaic_cac_protocol::evaluator::{
    deposit::DepositState,
    root_state::EvaluatorState,
    state::{StateMut, StateRead},
};
use mosaic_cac_types::{
    AllGarblingTableCommitments, ChallengeIndices, CircuitInputShares, CompletedSignatures,
    DepositAdaptors, DepositId, DepositInputs, HeapArray, InputPolynomialCommitments,
    OpenedGarblingSeeds, OpenedInputShares, OpenedOutputShares, OutputPolynomialCommitment,
    ReservedSetupInputShares, Sighashes, WideLabelWirePolynomialCommitments, WithdrawalAdaptors,
    WithdrawalAdaptorsChunk, WithdrawalInputs,
};
use mosaic_common::constants::{N_ADAPTOR_MSG_CHUNKS, N_INPUT_WIRES};

use crate::error::DbError;

/// In-memory storage for evaluator protocol state and cryptographic data.
#[derive(Debug, Clone, Default)]
pub struct StoredEvaluatorState {
    /// Root evaluator state machine state.
    pub state: EvaluatorState,
    /// Input polynomial commitments indexed by wire.
    pub input_polynomial_commitments: BTreeMap<usize, WideLabelWirePolynomialCommitments>,
    /// Output polynomial commitment.
    pub output_polynomial_commitment: Option<OutputPolynomialCommitment>,
    /// Garbling table commitments for all circuits.
    pub gt_commitments: Option<AllGarblingTableCommitments>,
    /// Challenge indices for verification using CaC.
    pub challenge_indices: Option<ChallengeIndices>,
    /// Shares for input wires, indexed by circuit.
    pub opened_input_shares: BTreeMap<usize, CircuitInputShares>,
    /// Shares for setup input wires at reserved circuit index.
    pub reserved_setup_input_shares: Option<ReservedSetupInputShares>,
    /// Shares for output wires for opened circuits.
    pub opened_output_shares: Option<OpenedOutputShares>,
    /// Opened garbling seeds.
    pub opened_garbling_seeds: Option<OpenedGarblingSeeds>,
    /// Per-deposit state indexed by `DepositId`.
    pub deposits: HashMap<DepositId, EvaluatorDepositState>,
}

impl StoredEvaluatorState {
    fn get_deposit_mut_or_default(&mut self, deposit_id: &DepositId) -> &mut EvaluatorDepositState {
        if !self.deposits.contains_key(deposit_id) {
            self.deposits
                .insert(*deposit_id, EvaluatorDepositState::default());
        };
        self.deposits.get_mut(deposit_id).unwrap()
    }

    fn get_deposit_or_err(
        &self,
        deposit_id: &DepositId,
    ) -> Result<&EvaluatorDepositState, DbError> {
        self.deposits
            .get(deposit_id)
            .ok_or_else(|| DbError::unknown_deposit(*deposit_id))
    }
}

/// Per-deposit state for evaluator state machine.
#[derive(Debug, Clone, Default)]
pub struct EvaluatorDepositState {
    /// Root state per Deposit.
    pub state: Option<DepositState>,
    /// Transaction sighashes for this deposit.
    pub sighashes: Option<Sighashes>,
    /// Values for deposit input wires.
    pub deposit_inputs: Option<DepositInputs>,
    /// Inputs for withdrawal input wires.
    pub withdrawal_inputs: Option<WithdrawalInputs>,
    /// Adaptor signatures for deposit input wires.
    pub deposit_adaptors: Option<DepositAdaptors>,
    /// Adaptor signatures for Withdrawal input wires, chunked in `N_ADAPTOR_MSG_CHUNKS` chunks.
    pub withdrawal_adaptors: HashMap<u8, WithdrawalAdaptorsChunk>,
    /// Completed adaptor signatures.
    pub completed_sigs: Option<CompletedSignatures>,
}

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
}
